package eval

import (
	"strings"
	"sync"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// PolicyEvaluator is the query layer over the IAM policy engine: it answers
// "can principal X perform action Y on resource Z?" and "does role R's trust
// policy admit principal P?" for the whole store. Ported from AWSHound's
// core/evaluation/policy_evaluator.py PolicyEvaluator together with the
// compressed-permissions cache (compressed_permissions.py) and the per-principal
// warm path of core/models/account_data.py (get_permissions,
// _compute_principal_key, bundle loading, SCP/RCP level construction).
//
// For a principal it resolves the identity policies (inline + attached-managed +
// group-inherited for users), the permissions boundary, and the account's
// ordered SCP/RCP levels from the store's public API, runs the engine's
// Compile/Combine, then compresses each effective statement to roaring bitmaps
// of ARN int-ids via the shared ArnIndex (ResolvePattern). The result is cached
// per principal by a content fingerprint so principals with fingerprint-equal
// inputs share a single entry (the Python two-level dedup cache).
//
// # Deliberate, decision-preserving divergences from the Python
//
//   - RCP denials get their own PermissionOutcome (OutcomeDeniedByRCP) rather
//     than folding into DENIED_BY_SCP, matching types.go's documented intent.
//   - The per-principal fingerprint keys on the raw (source, document) inputs
//     (not Python's normalized content hash). This is stricter — two principals
//     share an entry only when their sources and documents are byte-identical —
//     which yields slightly less sharing but guarantees byte-identical outputs
//     including AllowSources/BlockingSource. Allow/deny decisions are unchanged.
//   - The request context for a check is built lazily from the store inside
//     CanPerformAction/CheckTrustPolicy (buildPolicyVarContext, the port of
//     store.get_policy_variable_context), so callers pass only Python's per-call
//     request_context overlay (e.g. iam:PassedToService) as ctx, or nil for none.
//
// The cache-build partial resolution (cache_build_resolution.py
// filter_statements_inplace) IS ported, so account-scoped conditions are
// pre-resolved identically to the Python cache and the result does not depend on
// the caller populating account/org keys in ctx.
//
// A PolicyEvaluator is safe for concurrent use once the store is populated
// (the query phase); its caches are guarded and its scan-once indexes assume the
// store is stable during evaluation (ingestion has completed).
type PolicyEvaluator struct {
	store  *store.Store
	arn    *store.ArnIndex
	engine *IamPolicyEngine

	// Per-principal compressed-permissions cache, fingerprint-deduplicated.
	// principalToKey maps a principal ARN to its input fingerprint;
	// permsByKey holds the deduplicated compressed permissions.
	permMu         sync.RWMutex
	principalToKey map[string]string
	permsByKey     map[string]*compressedPermissions

	// Compiled-policy cache: a managed policy attached to many principals (or an
	// SCP shared by many accounts) compiles once. Keyed by (source, document).
	compileMu    sync.RWMutex
	compileCache map[string]compiledDoc

	// Pattern -> bitmap memoisation (the GPL-free counterpart of the store's
	// resolve_pattern_to_bitmap): many statements across fingerprints share a
	// resource pattern, so the universe scan is paid once per unique pattern.
	// The stored bitmap is treated as read-only and shared across statements.
	patternMu    sync.RWMutex
	patternCache map[string]*roaring.Bitmap

	// Per-account ordered SCP/RCP levels (root -> OU -> account), with the
	// policy-language versions of each org source. Computed once per account.
	orgLevelsMu    sync.Mutex
	scpLevelsCache map[string]levelsEntry
	rcpLevelsCache map[string]levelsEntry

	// Scan-once indexes over the (stable) store.
	accOnce       sync.Once
	accountsByID  map[string]*store.Account
	managedOnce   sync.Once
	managedByArn  map[string]*model.PolicyDetail
	orgOnce       sync.Once
	orgDataVal    *orgData
	trustOnce     sync.Once
	trustStateVal *trustState

	// Bucket-name -> metadata index for S3 resource lookups (S3 ARNs carry no
	// account in the ARN, so the account/region/tags come from the store).
	s3Once   sync.Once
	s3ByName map[string]*resourceMeta

	// ARN -> tags index for non-IAM/non-S3 service resources (KMS, EC2, Lambda,
	// SSM, EKS, CloudFormation), so aws:ResourceTag/* conditions on those targets
	// resolve against the resource's real tags instead of falling to attacker bias.
	// Only resources whose tags were actually collected appear here (ABSENT vs
	// UNKNOWN); account/region still derive from the ARN.
	resTagsOnce  sync.Once
	resTagsByArn map[string][]model.Tag

	groupIdxMu        sync.Mutex
	groupIdxByAccount map[string]map[string]*model.GroupDetail

	// Per-(role ARN, action) trust bitmap: the set of principal int-ids the
	// role's trust policy names (ignoring conditions). Fast-reject pre-filter.
	trustBMMu      sync.Mutex
	roleTrustCache map[string]*roaring.Bitmap

	// action -> PrincipalsWithAction(action, "*") bitmap, memoised for the
	// mandatory-identity edge pre-filter (PrincipalsWithActionAll). Read-only after
	// insertion.
	pwaMu    sync.Mutex
	pwaCache map[string]*roaring.Bitmap
}

// NewPolicyEvaluator returns an evaluator over the store, loading the bundled
// IAM action catalog to build the engine. Mirrors PolicyEvaluator.__init__ plus
// account_data._iam_policy_engine (which loads the catalog on first use).
func NewPolicyEvaluator(st *store.Store) (*PolicyEvaluator, error) {
	catalog, err := LoadBundled()
	if err != nil {
		return nil, err
	}
	return NewPolicyEvaluatorWithEngine(st, NewIamPolicyEngine(catalog)), nil
}

// NewPolicyEvaluatorWithEngine returns an evaluator over the store using a
// caller-supplied engine (for tests, or a custom action catalog).
func NewPolicyEvaluatorWithEngine(st *store.Store, engine *IamPolicyEngine) *PolicyEvaluator {
	return &PolicyEvaluator{
		store:             st,
		arn:               st.ARN(),
		engine:            engine,
		principalToKey:    make(map[string]string),
		permsByKey:        make(map[string]*compressedPermissions),
		compileCache:      make(map[string]compiledDoc),
		patternCache:      make(map[string]*roaring.Bitmap),
		scpLevelsCache:    make(map[string]levelsEntry),
		rcpLevelsCache:    make(map[string]levelsEntry),
		groupIdxByAccount: make(map[string]map[string]*model.GroupDetail),
		roleTrustCache:    make(map[string]*roaring.Bitmap),
	}
}

// -------------------------------------------------------------------------
// Store-derived helpers (functions/methods over the public store API)
// -------------------------------------------------------------------------

func (pe *PolicyEvaluator) ensureAccounts() {
	pe.accOnce.Do(func() {
		m := make(map[string]*store.Account)
		for _, a := range pe.store.Accounts() {
			m[a.ID] = a
		}
		pe.accountsByID = m
	})
}

// account returns the store account for id without the create-if-absent side
// effect of store.Account, and whether it exists.
func (pe *PolicyEvaluator) account(id string) (*store.Account, bool) {
	pe.ensureAccounts()
	a, ok := pe.accountsByID[id]
	return a, ok
}

func (pe *PolicyEvaluator) accountExists(id string) bool {
	_, ok := pe.account(id)
	return ok
}

func (pe *PolicyEvaluator) ensureManaged() {
	pe.managedOnce.Do(func() {
		m := make(map[string]*model.PolicyDetail)
		for _, a := range pe.store.Accounts() {
			for arn, p := range a.ManagedPolicies {
				if _, exists := m[arn]; !exists {
					m[arn] = p
				}
			}
		}
		pe.managedByArn = m
	})
}

// managedDoc returns a managed policy's default-version document string, or ""
// when the policy is unknown or has no default document. ARNs are globally
// unique (customer-managed embed the account id; AWS-managed are global), so a
// single ARN-keyed index covers Python's "this account's customer-managed +
// every AWS-managed" bundle set. Ported from account_data._default_policy_version.
func (pe *PolicyEvaluator) managedDoc(policyArn string) string {
	pe.ensureManaged()
	if p, ok := pe.managedByArn[policyArn]; ok {
		return p.DefaultPolicyDocument()
	}
	return ""
}

// groupByName resolves a group NAME (as carried in UserDetail.GroupList) to its
// group object within the account, via a per-account name index. Ports the
// user->group edge that Python reads from the principal_group table.
func (pe *PolicyEvaluator) groupByName(acct *store.Account, name string) *model.GroupDetail {
	pe.groupIdxMu.Lock()
	idx, ok := pe.groupIdxByAccount[acct.ID]
	if !ok {
		idx = make(map[string]*model.GroupDetail)
		for _, g := range acct.Groups {
			idx[g.GroupName] = g
		}
		pe.groupIdxByAccount[acct.ID] = idx
	}
	pe.groupIdxMu.Unlock()
	return idx[name]
}

// -------------------------------------------------------------------------
// CanPerformAction (policy_evaluator.can_perform_action)
// -------------------------------------------------------------------------

// CanPerformAction checks whether a principal can perform an action on a
// resource. Ported from policy_evaluator.can_perform_action.
//
// It collects the matched allow/deny statements for the action (resource-side
// matching via bitmaps with a policy-variable / wildcard-target regex fallback),
// then defers the allow/deny decision to the shared condition-aware resolver so
// the tri-state attacker-bias rule cannot drift. When no statement matches, the
// denial is attributed to a cause (implicit deny vs boundary/SCP/RCP clip).
//
// The request context is built internally from the store for this (principal,
// action, resource) via buildPolicyVarContext (the port of the Python query
// layer), so query-time keys — aws:PrincipalArn, aws:PrincipalTag/*,
// aws:PrincipalType, aws:username/userid, aws:ResourceAccount, aws:ResourceTag/*,
// and the *Known flags — resolve correctly rather than defaulting to UNKNOWN. A
// non-nil ctx is treated as a per-call OVERLAY (its Values, lower-cased, win over
// the store-derived ones) — how a PassRole-via-service processor injects
// iam:PassedToService; nil means no overlay. The base context is built lazily and
// at most once, only when a policy-variable resource pattern or a matched
// statement's condition actually needs it.
func (pe *PolicyEvaluator) CanPerformAction(principalArn, action, resourceArn string, ctx *RequestContext) *PermissionCheckResult {
	perms, err := pe.getPermissions(principalArn)
	if err != nil {
		return &PermissionCheckResult{Allowed: false, Outcome: OutcomeImplicitDeny}
	}

	stmtMatches, contextFactory := pe.permissionQuery(perms, principalArn, action, resourceArn, ctx)

	matchedAllows := collectMatched(perms.allowByAction.forAction(action), stmtMatches)
	denyStmts := perms.denyByAction.forAction(action)
	identityCoversAction := true
	for _, stmt := range denyStmts {
		if stmt.identityScoped {
			identityCoversAction = perms.identityCoversAction(action)
			break
		}
	}
	matchedDenies := collectMatched(denyStmts, func(stmt *compressedStatement) bool {
		return (!stmt.identityScoped || identityCoversAction) && stmtMatches(stmt)
	})

	if len(matchedAllows) == 0 && len(matchedDenies) == 0 {
		outcome, blocking := pe.classifyDeny(perms, action, stmtMatches)
		return &PermissionCheckResult{Allowed: false, Outcome: outcome, BlockingSource: blocking}
	}

	// Resolve conditions against the base context, overlaying any per-call ctx
	// (e.g. iam:PassedToService) on top of the store-derived values. The factory
	// is invoked only when a matched statement carries a condition.
	res := ResolveMatchedStatements(matchedAllows, matchedDenies, contextFactory)
	out := &PermissionCheckResult{
		Allowed:      res.Allowed,
		Denied:       res.Denied,
		Conditions:   res.Conditions,
		AllowSources: res.AllowSources,
		DenySources:  res.DenySources,
	}
	switch {
	case res.Allowed:
		out.Outcome = OutcomeAllowed
	case res.Denied:
		out.Outcome = OutcomeExplicitDeny
		if len(res.DenySources) > 0 {
			out.BlockingSource = res.DenySources[0]
		}
	default:
		// Matched allows existed but were all discarded (conditions FALSE) -> no
		// grant effectively applies -> implicit deny.
		out.Outcome = OutcomeImplicitDeny
	}
	return out
}

// permissionQuery builds the shared resource matcher and lazy condition
// context for one concrete authorization request. Direct resource grants use
// the same mechanics as identity permissions, but apply their guardrails
// independently because the resource policy supplies the Allow.
func (pe *PolicyEvaluator) permissionQuery(perms *compressedPermissions, principalArn, action, resourceArn string, ctx *RequestContext) (func(*compressedStatement) bool, ContextFactory) {
	var baseCtx *RequestContext
	baseContext := func() *RequestContext {
		if baseCtx == nil {
			baseCtx = pe.buildPolicyVarContext(principalArn, action, resourceArn)
		}
		return baseCtx
	}
	matchPattern := func(pattern, source string) bool {
		p := pattern
		if HasPolicyVariables(pattern) && pe.sourceSupportsVariables(perms, source) {
			resolved, ok := ResolvePolicyVariables(pattern, baseContext(), true)
			if !ok {
				return false
			}
			p = resolved
		}
		return resourceMatches(p, resourceArn)
	}
	stmtMatches := func(stmt *compressedStatement) bool {
		hasPositive := stmt.fallbackResource != nil
		if !stmt.isUniversal && hasPositive && !matchPattern(*stmt.fallbackResource, stmt.source) {
			return false
		}
		if !stmt.isUniversal && !hasPositive && stmt.fallbackNotResource == nil {
			return false
		}
		return stmt.fallbackNotResource == nil || !matchPattern(*stmt.fallbackNotResource, stmt.source)
	}
	return stmtMatches, func() *RequestContext {
		return overlayContext(baseContext(), ctx)
	}
}

// CheckDirectGrantConstraints applies the policy layers that still constrain a
// resource-based grant: all explicit denies, an attached permissions boundary,
// and each applicable SCP/RCP ceiling. Unlike CanPerformAction it does not
// require an identity Allow because the caller has already established a direct
// resource-policy Allow.
func (pe *PolicyEvaluator) CheckDirectGrantConstraints(principalArn, action, resourceArn string, ctx *RequestContext) *PermissionCheckResult {
	perms, err := pe.getPermissions(principalArn)
	if err != nil {
		return &PermissionCheckResult{Outcome: OutcomeImplicitDeny}
	}
	stmtMatches, contextFactory := pe.permissionQuery(perms, principalArn, action, resourceArn, ctx)
	denies := collectMatched(perms.denyByAction.forAction(action), stmtMatches)
	if denied := ResolveMatchedStatements(nil, denies, contextFactory); denied.Denied {
		out := &PermissionCheckResult{
			Denied:         true,
			DenySources:    denied.DenySources,
			Outcome:        OutcomeExplicitDeny,
			BlockingSource: firstSource(perms.denyByAction),
		}
		if len(denied.DenySources) > 0 {
			out.BlockingSource = denied.DenySources[0]
		}
		return out
	}

	var conditions []map[string]any
	requireAllow := func(index *compressedIndex, outcome PermissionOutcome) *PermissionCheckResult {
		res := ResolveMatchedStatements(collectMatched(index.forAction(action), stmtMatches), nil, contextFactory)
		if !res.Allowed {
			return &PermissionCheckResult{Outcome: outcome, BlockingSource: firstSource(index)}
		}
		conditions = append(conditions, res.Conditions...)
		return nil
	}
	if pe.principalHasPermissionsBoundary(principalArn) {
		// An attached boundary whose document was not collected cannot prove the
		// required Allow, so direct trust fails closed.
		if !perms.hasBoundary {
			return &PermissionCheckResult{Outcome: OutcomeDeniedByBoundary}
		}
		if blocked := requireAllow(perms.boundaryAllowByAction, OutcomeDeniedByBoundary); blocked != nil {
			return blocked
		}
	}
	if !strings.Contains(principalArn, ":role/aws-service-role/") {
		if perms.hasSCP && !perms.scpAllowPermitsAll {
			if blocked := requireAllow(perms.scpAllowByAction, OutcomeDeniedBySCP); blocked != nil {
				return blocked
			}
		}
		if perms.hasRCP && !perms.rcpAllowPermitsAll {
			if blocked := requireAllow(perms.rcpAllowByAction, OutcomeDeniedByRCP); blocked != nil {
				return blocked
			}
		}
	}
	return &PermissionCheckResult{Allowed: true, Outcome: OutcomeAllowed, Conditions: conditions}
}

func (pe *PolicyEvaluator) principalHasPermissionsBoundary(principalArn string) bool {
	accountID, ok := accountSegment(principalArn)
	if !ok {
		return false
	}
	acct, ok := pe.account(accountID)
	if !ok {
		return false
	}
	if user := acct.Users[principalArn]; user != nil {
		return user.PermissionsBoundary != nil
	}
	if role := acct.Roles[principalArn]; role != nil {
		return role.PermissionsBoundary != nil
	}
	return false
}

// collectMatched returns MatchedStatements for the subset of stmts that match
// the (already-bound) resource predicate. The compressed statement's condition
// and source are exactly what the shared resolver reads.
func collectMatched(stmts []*compressedStatement, matches func(*compressedStatement) bool) []MatchedStatement {
	var out []MatchedStatement
	for _, s := range stmts {
		if matches(s) {
			out = append(out, MatchedStatement{Condition: s.condition, Source: s.source})
		}
	}
	return out
}

// classifyDeny attributes a no-matching-statement denial to a cause. Ported from
// policy_evaluator._classify_deny, with one intended divergence: RCP clips
// report OutcomeDeniedByRCP (Python folds them into DENIED_BY_SCP). A guardrail
// that permits every action (FullAWSAccess-only) short-circuits and never
// causes a denial. The blocking source is chosen deterministically (the smallest
// source across the guardrail's index) so output is reproducible.
func (pe *PolicyEvaluator) classifyDeny(perms *compressedPermissions, action string, stmtMatches func(*compressedStatement) bool) (PermissionOutcome, string) {
	covers := func(index *compressedIndex) bool {
		for _, s := range index.forAction(action) {
			if stmtMatches(s) {
				return true
			}
		}
		return false
	}
	if !covers(perms.identityAllowByAction) {
		return OutcomeImplicitDeny, ""
	}
	if perms.hasBoundary && !covers(perms.boundaryAllowByAction) {
		return OutcomeDeniedByBoundary, firstSource(perms.boundaryAllowByAction)
	}
	if perms.hasSCP && !perms.scpAllowPermitsAll && !covers(perms.scpAllowByAction) {
		return OutcomeDeniedBySCP, firstSource(perms.scpAllowByAction)
	}
	if perms.hasRCP && !perms.rcpAllowPermitsAll && !covers(perms.rcpAllowByAction) {
		return OutcomeDeniedByRCP, firstSource(perms.rcpAllowByAction)
	}
	return OutcomeImplicitDeny, ""
}

// firstSource returns a representative blocking source from a guardrail index.
// Python returns the insertion-order-first statement's source; the Go port
// returns the lexicographically smallest source so the result is reproducible
// across runs despite randomized map iteration (this is deny enrichment, not
// edge existence).
func firstSource(index *compressedIndex) string {
	best := ""
	found := false
	for _, s := range index.statements {
		if !found || s.source < best {
			best, found = s.source, true
		}
	}
	return best
}

// sourceSupportsVariables reports whether the policy source of a grant uses the
// variable-aware policy language version (2012-10-17). Ported from
// account_data.policy_source_supports_variables (the grant source is
// "<policy-source>/<sid>", so the sid segment is stripped).
func (pe *PolicyEvaluator) sourceSupportsVariables(perms *compressedPermissions, grantSource string) bool {
	src := grantSource
	if i := strings.LastIndex(grantSource, "/"); i >= 0 {
		src = grantSource[:i]
	}
	return perms.sourceVersions[src] == "2012-10-17"
}

// -------------------------------------------------------------------------
// PrincipalsWithAction (policy_evaluator.principals_with_action, resource-aware)
// -------------------------------------------------------------------------

// PrincipalsWithAction returns a roaring bitmap of principal ARN int-ids (from
// the shared ArnIndex) for every user/role whose effective permissions grant an
// allow for action on some resource matching resourcePattern. Ported from
// policy_evaluator.principals_with_action / principals_with_action_bm, made
// resource-aware via the pattern's resolved bitmap so the returned set is the
// tight edge-candidate set an attack-path edge processor pre-filters with.
//
// The result shares the ArnIndex id-space with RoleTrustBitmap, so a caller can
// intersect the two bitmaps to find principals that BOTH can-assume a role AND
// hold an IAM-side allow, in one bitmap AND regardless of which side is more
// selective.
//
// Soundness note: for concrete (variable-free) statement resources the check is
// exact bitmap overlap, sound whenever the query targets are interned ARNs (the
// common case — the pattern resolves to known resources the caller then queries
// with CanPerformAction). Statements with policy-variable resources, Resource:"*",
// or a pure NotResource cannot be excluded statically and are always included.
// Only ALLOW statements are considered — a deny-only principal can never yield an
// edge, so excluding it drops nothing.
func (pe *PolicyEvaluator) PrincipalsWithAction(action, resourcePattern string) *roaring.Bitmap {
	ts := pe.ensureTrustState()
	targetBM := pe.arn.ResolvePattern(resourcePattern)
	out := roaring.New()
	for _, p := range ts.principalRefs {
		perms, err := pe.getPermissions(p.arn)
		if err != nil {
			continue
		}
		for _, s := range perms.allowByAction.forAction(action) {
			if pe.statementCouldMatch(s, targetBM) {
				out.Add(p.id)
				break
			}
		}
	}
	return out
}

// PrincipalsWithActionAnyResource returns every user/role that has an effective
// allow statement for action before binding that statement to an interned target.
// This is the safe candidate set for resource families such as S3 whose object
// ARNs are deliberately not interned: a concrete object-only Resource pattern
// must remain a candidate even though its pre-resolved bitmap is empty.
func (pe *PolicyEvaluator) PrincipalsWithActionAnyResource(action string) *roaring.Bitmap {
	return pe.PrincipalsWithAnyActionAnyResource([]string{action})
}

// PrincipalsWithAnyActionAnyResource is the multi-action form used to build one
// coarse, safe candidate set for an edge family in a single principal scan.
func (pe *PolicyEvaluator) PrincipalsWithAnyActionAnyResource(actions []string) *roaring.Bitmap {
	ts := pe.ensureTrustState()
	out := roaring.New()
	for _, p := range ts.principalRefs {
		perms, err := pe.getPermissions(p.arn)
		if err != nil {
			continue
		}
		if perms.allowByAction.hasAnyAction(actions) {
			out.Add(p.id)
		}
	}
	return out
}

// PrincipalActionMasksAnyResource returns the per-principal bit mask of
// effective allow statements for actions (bit i corresponds to actions[i]). It
// keeps the same evicted-resource safety as PrincipalsWithAnyActionAnyResource
// while allowing a resource evaluator to skip unrelated action checks.
func (pe *PolicyEvaluator) PrincipalActionMasksAnyResource(actions []string) map[uint32]uint64 {
	if len(actions) > 64 {
		panic("eval: action mask supports at most 64 actions")
	}
	ts := pe.ensureTrustState()
	out := make(map[uint32]uint64)
	for _, p := range ts.principalRefs {
		perms, err := pe.getPermissions(p.arn)
		if err != nil {
			continue
		}
		if mask := perms.allowByAction.actionMask(actions); mask != 0 {
			out[p.id] = mask
		}
	}
	return out
}

// PrincipalsWithActionAll returns (and memoises) the principal-id bitmap for
// PrincipalsWithAction(action, "*") — every principal with an effective identity
// allow for the action on any resource. This is the candidate pre-filter for
// edge families where an identity allow is mandatory (IdentityGoverned,
// MandatoryPolicy): a principal absent from the set has no allow statement that
// could match an interned target, so it can never yield such an edge and its
// per-(principal,resource) CanPerformAction calls can be skipped. Mirrors the
// Python edge processors' principals_with_action pre-filter.
//
// The returned bitmap is shared and MUST be treated as read-only (callers do
// Contains only); the per-action scan runs at most once per evaluator.
func (pe *PolicyEvaluator) PrincipalsWithActionAll(action string) *roaring.Bitmap {
	pe.pwaMu.Lock()
	defer pe.pwaMu.Unlock()
	if bm, ok := pe.pwaCache[action]; ok {
		return bm
	}
	bm := pe.PrincipalsWithAction(action, "*")
	if pe.pwaCache == nil {
		pe.pwaCache = make(map[string]*roaring.Bitmap)
	}
	pe.pwaCache[action] = bm
	return bm
}

// statementCouldMatch reports whether a compressed statement could match any
// resource in targetBM. Concrete resources use exact bitmap overlap; universal /
// policy-variable / pure-NotResource statements are conservatively included.
func (pe *PolicyEvaluator) statementCouldMatch(s *compressedStatement, targetBM *roaring.Bitmap) bool {
	if s.isUniversal {
		return true
	}
	if s.matchedArns != nil {
		return s.matchedArns.Intersects(targetBM)
	}
	if s.fallbackResource != nil && !HasPolicyVariables(*s.fallbackResource) {
		return pe.resolvePattern(*s.fallbackResource).Intersects(targetBM)
	}
	// matchedArns nil and not universal: policy-variable fallback or pure
	// NotResource — cannot exclude statically.
	return true
}
