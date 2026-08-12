package eval

import (
	"crypto/sha256"
	"errors"
	"hash"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// This file builds and caches a principal's compressed effective permissions:
// the bitmap-backed query form (compressed_permissions.py), the per-principal
// resolution and fingerprint-dedup pipeline (the warm path of account_data.py's
// get_permissions), and the AWS Organizations SCP/RCP level construction that
// feeds it (_org_policy_levels).

// -------------------------------------------------------------------------
// Compressed permissions (compressed_permissions.py)
// -------------------------------------------------------------------------

// compressedStatement is one bundled effective statement. Unlike the eager
// Python-shaped index, it retains the compact action set for lazy views.
//
// matchedArns/excludedArns are optional, lazily resolved bitmaps used only by
// resource-aware PrincipalsWithAction prefilters. Point CanPerformAction queries
// match fallback* directly against their one target; pre-resolving every policy
// pattern over the whole ARN universe while warming a principal would make a
// query about one action compile every unrelated service pattern. isUniversal
// is the Resource:"*" sentinel.
type compressedStatement struct {
	condition           Condition
	source              string
	matchedArns         *roaring.Bitmap
	excludedArns        *roaring.Bitmap
	fallbackResource    *string
	fallbackNotResource *string
	isUniversal         bool
	actions             ActionSet
	complement          bool
	identityScoped      bool
}

// compressedIndex stores each logical statement once and builds only the
// action views the graph actually asks for. AWSHound analysis queries a small,
// fixed subset of the ~20k action catalog; eagerly materialising every service
// wildcard action for every unique principal policy set was the dominant heap
// cost. The lazy views are safe to share across principals with the same
// fingerprint and across concurrent edge workers.
type compressedIndex struct {
	mu         sync.RWMutex
	statements []*compressedStatement
	byAction   map[string][]*compressedStatement
}

func (idx *compressedIndex) forAction(action string) []*compressedStatement {
	if idx == nil {
		return nil
	}
	idx.mu.RLock()
	stmts, ok := idx.byAction[action]
	idx.mu.RUnlock()
	if ok {
		return stmts
	}

	stmts = make([]*compressedStatement, 0)
	for _, s := range idx.statements {
		_, named := s.actions[action]
		if named != s.complement { // concrete: named; complement: not named
			stmts = append(stmts, s)
		}
	}
	idx.mu.Lock()
	if existing, ok := idx.byAction[action]; ok {
		stmts = existing
	} else {
		idx.byAction[action] = stmts
	}
	idx.mu.Unlock()
	return stmts
}

func (idx *compressedIndex) hasAnyAction(actions []string) bool {
	if idx == nil {
		return false
	}
	for _, s := range idx.statements {
		for _, action := range actions {
			_, named := s.actions[action]
			if named != s.complement {
				return true
			}
		}
	}
	return false
}

func (idx *compressedIndex) actionMask(actions []string) uint64 {
	if idx == nil {
		return 0
	}
	var mask uint64
	for _, s := range idx.statements {
		for i, action := range actions {
			_, named := s.actions[action]
			if named != s.complement {
				mask |= uint64(1) << i
			}
		}
	}
	return mask
}

// compressedPermissions is a principal's permissions in the bitmap-backed query
// form. Ported from compressed_permissions.py CompressedPermissions, plus
// sourceVersions (the policy-language version per policy source) which the
// fallback resource matcher consults to decide whether ${...} variables in a
// pattern are substituted (Python threads this through
// store.policy_source_supports_variables).
type compressedPermissions struct {
	allowByAction         *compressedIndex
	denyByAction          *compressedIndex
	identityAllowByAction *compressedIndex
	boundaryAllowByAction *compressedIndex
	scpAllowByAction      *compressedIndex
	rcpAllowByAction      *compressedIndex
	hasBoundary           bool
	hasSCP                bool
	hasRCP                bool
	scpAllowPermitsAll    bool
	rcpAllowPermitsAll    bool
	identityActionScope   []ActionSet
	sourceVersions        map[string]string
}

// compress adapts the engine's EffectivePermissions into the bitmap-backed query
// form. Ported from compressed_permissions.py compress_effective.
func (pe *PolicyEvaluator) compress(eff *EffectivePermissions) *compressedPermissions {
	allowByAction := pe.bundle(eff.AllowByAction)
	var identityAllowByAction *compressedIndex
	if !eff.HasBoundary && (!eff.HasSCP || eff.ScpAllowPermitsAll) && (!eff.HasRCP || eff.RcpAllowPermitsAll) {
		// With no effective allow ceiling, the final allow layer is the identity
		// layer. Sharing the read-only index halves the dominant cached statement
		// set on ordinary org accounts.
		identityAllowByAction = allowByAction
	} else {
		identityAllowByAction = pe.bundle(eff.IdentityAllowByAction)
	}
	return &compressedPermissions{
		allowByAction:         allowByAction,
		denyByAction:          pe.bundle(eff.DenyByAction),
		identityAllowByAction: identityAllowByAction,
		boundaryAllowByAction: pe.bundle(eff.BoundaryAllowByAction),
		scpAllowByAction:      pe.bundle(eff.ScpAllowByAction),
		rcpAllowByAction:      pe.bundle(eff.RcpAllowByAction),
		hasBoundary:           eff.HasBoundary,
		hasSCP:                eff.HasSCP,
		hasRCP:                eff.HasRCP,
		scpAllowPermitsAll:    eff.ScpAllowPermitsAll,
		rcpAllowPermitsAll:    eff.RcpAllowPermitsAll,
		identityActionScope:   eff.IdentityActionScope,
	}
}

func (p *compressedPermissions) identityCoversAction(action string) bool {
	for _, actions := range p.identityActionScope {
		if _, ok := actions[action]; ok {
			return true
		}
	}
	return false
}

// bundle wraps each logical EffectiveStatement once; compressedIndex creates
// its shared per-action views on demand.
func (pe *PolicyEvaluator) bundle(effs []*EffectiveStatement) *compressedIndex {
	out := &compressedIndex{
		statements: make([]*compressedStatement, 0, len(effs)),
		byAction:   make(map[string][]*compressedStatement),
	}
	for _, eff := range effs {
		out.statements = append(out.statements, pe.makeStatement(eff))
	}
	return out
}

// makeStatement builds a compact compressedStatement. Resource-pattern bitmaps
// are intentionally resolved only by the resource-aware candidate API.
func (pe *PolicyEvaluator) makeStatement(e *EffectiveStatement) *compressedStatement {
	cs := &compressedStatement{condition: e.Condition, source: e.Source, actions: e.Actions, complement: e.Complement, identityScoped: e.IdentityScoped}
	if e.Resource != nil {
		if *e.Resource == "*" {
			cs.isUniversal = true
		} else {
			r := *e.Resource
			cs.fallbackResource = &r
		}
	}
	if e.NotResource != nil {
		nr := *e.NotResource
		cs.fallbackNotResource = &nr
	}
	return cs
}

// resolvePattern returns the (shared, read-only) bitmap of interned ARN int-ids
// matching pattern, memoised across statements and principals. Ported from
// compressed_permissions.py _resolve_to_bitmap delegating to
// store.resolve_pattern_to_bitmap. The stored bitmap is only ever read
// (Contains/Intersects), so it is safe to share.
func (pe *PolicyEvaluator) resolvePattern(pattern string) *roaring.Bitmap {
	pe.patternMu.RLock()
	bm, ok := pe.patternCache[pattern]
	pe.patternMu.RUnlock()
	if ok {
		return bm
	}
	resolved := pe.arn.ResolvePattern(pattern)
	pe.patternMu.Lock()
	if existing, ok := pe.patternCache[pattern]; ok {
		resolved = existing
	} else {
		pe.patternCache[pattern] = resolved
	}
	pe.patternMu.Unlock()
	return resolved
}

// -------------------------------------------------------------------------
// Per-principal permissions (account_data.get_permissions + fingerprint)
// -------------------------------------------------------------------------

var (
	errBadArn         = errors.New("eval: cannot determine account from ARN")
	errNoAccount      = errors.New("eval: account not found in store")
	errEntityNotFound = errors.New("eval: entity not found in store")
)

// policyDoc is one (source, url-encoded-document) input to compilation.
type policyDoc struct {
	source string
	doc    string
}

// compiledDoc is a cached compiled policy together with its policy-language
// version (for the variable-support gate).
type compiledDoc struct {
	cp      *CompiledPolicy
	version string
}

// getPermissions returns a principal's compressed effective permissions,
// computing (and caching by fingerprint) on a miss. Ported from
// account_data.get_permissions: fast path (principal already mapped to a warmed
// fingerprint), then ARN/account validation, then fingerprint-dedup, then engine
// evaluation. The Python concurrent-warm Event coordination is replaced by a
// harmless recompute-and-setdefault (identical inputs yield identical output).
func (pe *PolicyEvaluator) getPermissions(principalArn string) (*compressedPermissions, error) {
	pe.permMu.RLock()
	if key, ok := pe.principalToKey[principalArn]; ok {
		if cp, ok := pe.permsByKey[key]; ok {
			pe.permMu.RUnlock()
			return cp, nil
		}
	}
	pe.permMu.RUnlock()

	accountID, ok := accountSegment(principalArn)
	if !ok || accountID == "" {
		return nil, errBadArn
	}
	acct, ok := pe.account(accountID)
	if !ok {
		return nil, errNoAccount
	}

	idDocs, boundaryDocs, entityType, err := pe.collectDocuments(acct, principalArn)
	if err != nil {
		return nil, err
	}

	key := fingerprint(entityType, accountID, idDocs, boundaryDocs)

	pe.permMu.RLock()
	cp, ok := pe.permsByKey[key]
	pe.permMu.RUnlock()
	if ok {
		pe.permMu.Lock()
		pe.principalToKey[principalArn] = key
		pe.permMu.Unlock()
		return cp, nil
	}

	cp = pe.computePermissions(accountID, idDocs, boundaryDocs)

	pe.permMu.Lock()
	if existing, ok := pe.permsByKey[key]; ok {
		cp = existing // setdefault: first writer wins.
	} else {
		pe.permsByKey[key] = cp
	}
	pe.principalToKey[principalArn] = key
	pe.permMu.Unlock()
	return cp, nil
}

// collectDocuments gathers the (source, document) inputs for a principal:
// inline + attached-managed policies, plus (for users) each group's inline +
// attached-managed policies, and the permission-boundary document. Ported from
// account_data._collect_identity_documents and _collect_boundary_documents,
// preserving their order (principal inline, principal managed, then per group:
// group inline, group managed) so grant/source ordering matches.
//
// A managed policy that is missing or has no default-version document is skipped
// (Python drops it). A boundary is included only when its policy exists and has a
// default document — a boundary attachment pointing at a missing policy imposes
// no ceiling, exactly as in Python (an empty boundary policy that DID load still
// imposes a block-everything ceiling, handled in computePermissions).
func (pe *PolicyEvaluator) collectDocuments(acct *store.Account, principalArn string) (idDocs, boundaryDocs []policyDoc, entityType string, err error) {
	var (
		inline      []model.InlinePolicy
		attached    []model.AttachedPolicy
		boundaryArn string
		groupNames  []string
	)
	switch {
	case acct.Users[principalArn] != nil:
		u := acct.Users[principalArn]
		entityType, inline, attached, groupNames = "user", u.UserPolicyList, u.AttachedManagedPols, u.GroupList
		if u.PermissionsBoundary != nil {
			boundaryArn = u.PermissionsBoundary.PermissionsBoundaryArn
		}
	case acct.Roles[principalArn] != nil:
		r := acct.Roles[principalArn]
		entityType, inline, attached = "role", r.RolePolicyList, r.AttachedManagedPols
		if r.PermissionsBoundary != nil {
			boundaryArn = r.PermissionsBoundary.PermissionsBoundaryArn
		}
	case acct.Groups[principalArn] != nil:
		g := acct.Groups[principalArn]
		entityType, inline, attached = "group", g.GroupPolicyList, g.AttachedManagedPols
	default:
		return nil, nil, "", errEntityNotFound
	}

	for _, ip := range inline {
		idDocs = append(idDocs, policyDoc{source: ip.PolicyName, doc: ip.PolicyDocument})
	}
	for _, ap := range attached {
		if doc := pe.managedDoc(ap.PolicyArn); doc != "" {
			idDocs = append(idDocs, policyDoc{source: ap.PolicyArn, doc: doc})
		}
	}
	if entityType == "user" {
		for _, name := range groupNames {
			grp := pe.groupByName(acct, name)
			if grp == nil {
				continue
			}
			for _, ip := range grp.GroupPolicyList {
				idDocs = append(idDocs, policyDoc{source: ip.PolicyName, doc: ip.PolicyDocument})
			}
			for _, ap := range grp.AttachedManagedPols {
				if doc := pe.managedDoc(ap.PolicyArn); doc != "" {
					idDocs = append(idDocs, policyDoc{source: ap.PolicyArn, doc: doc})
				}
			}
		}
	}
	if boundaryArn != "" {
		if doc := pe.managedDoc(boundaryArn); doc != "" {
			boundaryDocs = append(boundaryDocs, policyDoc{source: boundaryArn, doc: doc})
		}
	}
	return idDocs, boundaryDocs, entityType, nil
}

// computePermissions runs the engine over a principal's collected documents and
// compresses the result. Ported from the engine branch of
// account_data.get_permissions (compile identity + boundary, gather SCP/RCP
// levels, combine, compress, then filter_statements_inplace).
func (pe *PolicyEvaluator) computePermissions(accountID string, idDocs, boundaryDocs []policyDoc) *compressedPermissions {
	sourceVersions := make(map[string]string)
	record := func(source, version string) {
		if v, ok := sourceVersions[source]; ok {
			if v != version {
				sourceVersions[source] = "" // conflicting versions -> unsupported (Python: set len>1 -> None).
			}
			return
		}
		sourceVersions[source] = version
	}

	var idGrants []Grant
	for _, d := range idDocs {
		cd := pe.compileDoc(d.source, d.doc)
		idGrants = append(idGrants, cd.cp.Grants...)
		record(d.source, cd.version)
	}
	identity := &CompiledPolicy{Grants: idGrants}

	var boundary *CompiledPolicy
	if len(boundaryDocs) > 0 {
		var bGrants []Grant
		for _, d := range boundaryDocs {
			cd := pe.compileDoc(d.source, d.doc)
			bGrants = append(bGrants, cd.cp.Grants...)
			record(d.source, cd.version)
		}
		boundary = &CompiledPolicy{Grants: bGrants}
	}

	scp := pe.orgLevels(accountID, false)
	rcp := pe.orgLevels(accountID, true)
	for src, v := range scp.versions {
		record(src, v)
	}
	for src, v := range rcp.versions {
		record(src, v)
	}

	eff := pe.engine.Combine(identity, boundary, scp.levels, rcp.levels)
	cp := pe.compress(eff)
	cp.sourceVersions = sourceVersions
	pe.applyCacheBuildFilter(cp, accountID)
	return cp
}

// compileDoc parses and compiles a policy document once, cached by (source,
// document). Ported from account_data._compile_cached. A parse failure compiles
// to zero grants (Python only stores dict documents; a malformed one never
// reaches the engine).
func (pe *PolicyEvaluator) compileDoc(source, doc string) compiledDoc {
	cacheKey := source + "\x00" + doc
	pe.compileMu.RLock()
	cd, ok := pe.compileCache[cacheKey]
	pe.compileMu.RUnlock()
	if ok {
		return cd
	}

	pol, err := ParsePolicyDocument(doc)
	if err != nil || pol == nil {
		cd = compiledDoc{cp: &CompiledPolicy{}}
	} else {
		cd = compiledDoc{cp: pe.engine.Compile(pol, source), version: pol.Version}
	}

	pe.compileMu.Lock()
	if existing, ok := pe.compileCache[cacheKey]; ok {
		cd = existing
	} else {
		pe.compileCache[cacheKey] = cd
	}
	pe.compileMu.Unlock()
	return cd
}

// fingerprint is a principal's input fingerprint: entity type, account id
// (standing in for the account-wide SCP/RCP set, as in Python), and the sorted
// (source, document) pairs of its identity and boundary policies. Two principals
// with the same fingerprint compile byte-identically and share a cache entry.
// Ported in spirit from account_data._compute_principal_key (content-hashed),
// keyed on raw inputs rather than the normalized form (see the type doc).
func fingerprint(entityType, accountID string, idDocs, boundaryDocs []policyDoc) string {
	h := sha256.New()
	h.Write([]byte(entityType))
	h.Write([]byte{0})
	h.Write([]byte(accountID))
	h.Write([]byte{0})
	writeDocKeys(h, idDocs)
	h.Write([]byte{0})
	writeDocKeys(h, boundaryDocs)
	return string(h.Sum(nil))
}

// writeDocKeys writes the sorted (source, document) pairs into the fingerprint
// hash. Sorting makes the fingerprint independent of collection order; two
// principals with the same document SET share an entry (decisions are identical,
// only trace order could differ, matching Python's order-agnostic content hash).
func writeDocKeys(h hash.Hash, docs []policyDoc) {
	keys := make([]string, 0, len(docs))
	for _, d := range docs {
		keys = append(keys, d.source+"\x01"+d.doc)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0x02})
	}
}

// -------------------------------------------------------------------------
// AWS Organizations levels (account_data._org_policy_levels + org helpers)
// -------------------------------------------------------------------------

// orgPolicyRef is an SCP or RCP flattened to the fields the level builder needs.
type orgPolicyRef struct {
	arn        string
	content    string
	accountIDs []string
	targets    []model.OrgPolicyTarget
}

// orgData is the store's Organizations payload, gathered once: the per-account
// OU path map, the organization id, and the SCP/RCP policies. Mirrors the state
// account_data keeps in _organization_data / _scp_policies_by_account.
type orgData struct {
	hasOrg          bool
	orgID           string
	accountOrgPaths map[string]string
	scpRefs         []orgPolicyRef
	rcpRefs         []orgPolicyRef
	memberAccounts  map[string]bool // union of SCP/RCP AccountIds (org-membership fallback).
}

func (pe *PolicyEvaluator) orgDataOnce() *orgData {
	pe.orgOnce.Do(func() {
		od := &orgData{accountOrgPaths: map[string]string{}, memberAccounts: map[string]bool{}}
		for _, acct := range pe.store.Accounts() {
			if root := acct.OrganizationRecord(); root != nil && !od.hasOrg {
				od.hasOrg = true
				od.orgID = root.Organization.Id
				for k, v := range root.AccountOrgPaths {
					od.accountOrgPaths[k] = v
				}
			}
			for _, p := range acct.SCPPolicyList() {
				od.scpRefs = append(od.scpRefs, orgPolicyRef{arn: p.Arn, content: p.Content, accountIDs: p.AccountIds, targets: p.Targets})
			}
			for _, p := range acct.RCPPolicyList() {
				od.rcpRefs = append(od.rcpRefs, orgPolicyRef{arn: p.Arn, content: p.Content, accountIDs: p.AccountIds, targets: p.Targets})
			}
		}
		for _, r := range od.scpRefs {
			for _, a := range r.accountIDs {
				od.memberAccounts[a] = true
			}
		}
		for _, r := range od.rcpRefs {
			for _, a := range r.accountIDs {
				od.memberAccounts[a] = true
			}
		}
		pe.orgDataVal = od
	})
	return pe.orgDataVal
}

// orgPathForAccount returns the account's aws:PrincipalOrgPaths-style path, or ""
// when org data is absent or the account is not a member. Ported from
// _queries/organizations.organization_path_for_account.
func (od *orgData) orgPathForAccount(accountID string) string {
	if accountID == "" || !od.hasOrg {
		return ""
	}
	return od.accountOrgPaths[accountID]
}

// orgIDForAccount returns the organization id iff accountID is a known member
// (present in the store, or in some SCP/RCP AccountIds list). Ported from
// _queries/organizations.organization_id_for_account.
func (pe *PolicyEvaluator) orgIDForAccount(accountID string) string {
	od := pe.orgDataOnce()
	if accountID == "" || !od.hasOrg || od.orgID == "" {
		return ""
	}
	if pe.accountExists(accountID) || od.memberAccounts[accountID] {
		return od.orgID
	}
	return ""
}

// levelsEntry caches an account's compiled org-policy levels and the source
// versions of those org policies.
type levelsEntry struct {
	levels   [][]*CompiledPolicy
	versions map[string]string
}

// orgLevels returns the ordered, per-level compiled SCP (rcp=false) or RCP
// (rcp=true) policies for an account, cached per account. Ported from
// account_data._org_policy_levels / _scp_levels_for_account /
// _rcp_levels_for_account.
//
// With org hierarchy data: levels run root -> each OU on the account's path ->
// the account, each level the union of policies attached there; an empty level
// is omitted (the FullAWSAccess-present default). Without hierarchy data (no
// path / no org): a single flat level of every policy whose AccountIds include
// the account.
func (pe *PolicyEvaluator) orgLevels(accountID string, rcp bool) levelsEntry {
	pe.orgLevelsMu.Lock()
	defer pe.orgLevelsMu.Unlock()

	cache := pe.scpLevelsCache
	if rcp {
		cache = pe.rcpLevelsCache
	}
	if e, ok := cache[accountID]; ok {
		return e
	}

	od := pe.orgDataOnce()
	refs := od.scpRefs
	if rcp {
		refs = od.rcpRefs
	}

	versions := make(map[string]string)
	compile := func(r orgPolicyRef) *CompiledPolicy {
		cd := pe.compileDoc(r.arn, r.content)
		versions[r.arn] = cd.version
		return cd.cp
	}

	var levels [][]*CompiledPolicy
	path := od.orgPathForAccount(accountID)
	if path == "" || !od.hasOrg {
		var flat []*CompiledPolicy
		for _, r := range refs {
			if slices.Contains(r.accountIDs, accountID) {
				flat = append(flat, compile(r))
			}
		}
		if len(flat) > 0 {
			levels = [][]*CompiledPolicy{flat}
		}
	} else {
		var levelIDs []string
		for _, seg := range strings.Split(path, "/") {
			if seg != "" && !strings.HasPrefix(seg, "o-") {
				levelIDs = append(levelIDs, seg)
			}
		}
		levelIDs = append(levelIDs, accountID)

		byTarget := make(map[string][]orgPolicyRef)
		for _, r := range refs {
			for _, t := range r.targets {
				byTarget[t.TargetId] = append(byTarget[t.TargetId], r)
			}
		}
		for _, lid := range levelIDs {
			attached := byTarget[lid]
			if len(attached) == 0 {
				continue
			}
			lvl := make([]*CompiledPolicy, 0, len(attached))
			for _, r := range attached {
				lvl = append(lvl, compile(r))
			}
			levels = append(levels, lvl)
		}
	}

	entry := levelsEntry{levels: levels, versions: versions}
	cache[accountID] = entry
	return entry
}
