// Package edges ports AWSHound's attack-path edge processors
// (core/graph/edges/) into Go. Each family lives in its own file and exposes a
// single `<Family>Edges(*store.Store, *eval.PolicyEvaluator) []*graph.Edge`
// entry point that iterates the store and returns that family's edges.
//
// This file ports the iam_manipulation family
// (core/graph/edges/iam_manipulation/): the ~26 policy / permissions-boundary /
// group-membership / user-and-group-lifecycle primitives, plus the three
// escalation composites CanUpdateSelfPolicy, CanUpdateOtherPolicy, and
// CanCreateAndAccessAdminUser.
//
// Fidelity notes:
//   - Candidate principals are users + roles only (Python's
//     get_all_principal_arns excludes groups); groups appear only as edge
//     *targets*.
//   - The Python composites read already-emitted base edges from a cross-family
//     EdgeView. This Go entry point receives only (store, evaluator), so it
//     self-computes every base edge it needs. The composites are effectively
//     intra-account (a re-permission edge is always same-account, and a
//     qualifying pair needs BOTH a control and a re-permission edge to the same
//     dest), so the whole family is processed per account. The cross-family
//     control edges CanUpdateOtherPolicy consumes (AssumeRole, CreateAccessKey,
//     CreateLoginProfile, UpdateLoginProfile) are recomputed here with the exact
//     gating of their own processors but are NOT emitted (their families emit
//     them).
package edges

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// iamManipMaxWorkers overrides the per-account fan-out width when > 0; 0 defers to
// the GOAWSHOUND_EDGE_WORKERS env var, then runtime.NumCPU(). Tests set it to force
// sequential (=1) execution to diff against the parallel build.
var iamManipMaxWorkers = 0

// iamManipWorkers resolves the per-account fan-out width: the test override, else
// GOAWSHOUND_EDGE_WORKERS (an operator escape hatch — set it to 1 to fall back to
// the original sequential build if concurrency is ever suspect), else NumCPU. It
// is read once per build (one call per IAMManipulationEdges), so the env lookup is
// negligible.
func iamManipWorkers() int {
	if iamManipMaxWorkers > 0 {
		return iamManipMaxWorkers
	}
	if v := os.Getenv("GOAWSHOUND_EDGE_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return runtime.NumCPU()
}

// iamManipulationUnits reports iam_manipulation's finer-grained progress unit
// count — one per account, matching the per-account tick in iamManipulationEdges
// — so the Build edges stage can grow its denominator and this long straggler
// advances account-by-account instead of sitting on a single per-family tick for
// the whole (often >1h) run. See edges.edgeFamily.
func iamManipulationUnits(s *store.Store) int { return len(s.Accounts()) }

// IAMManipulationEdges emits the iam_manipulation family's edges for every
// account in the store. Accounts are processed in ascending id order so output
// is deterministic. The action->principals pre-filter bitmaps are global, so
// they are memoised across accounts.
func IAMManipulationEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	return iamManipulationEdges(s, pe, nil)
}

// iamManipulationEdges is IAMManipulationEdges with an optional per-account
// progress tick: onItem, when non-nil, is called once after each account's edges
// are built, so the registry can advance the Build edges bar account-by-account
// (the account loop is where this family spends its time — full CanPerformAction
// simulation over principals×resources per account). onItem is called exactly
// iamManipulationUnits(s) times, matching the denominator growth. A nil onItem
// reproduces the original behavior for direct callers.
func iamManipulationEdges(s *store.Store, pe *eval.PolicyEvaluator, onItem func()) []*graph.Edge {
	memo := newIamManipMemo(s, pe)
	accts := s.Accounts()
	sort.Slice(accts, func(i, j int) bool { return accts[i].ID < accts[j].ID })

	// Each account's edges are minutes of CanPerformAction simulation over its
	// principals×resources, and accounts are independent: iamManipAccountEdges
	// builds a private iamManipState and only shares the (thread-safe) evaluator,
	// the read-only store, and the mutex-guarded memo. So fan the per-account work
	// out over a bounded worker pool. Results are written to a per-account slot and
	// concatenated in sorted order afterward, so the emitted edge order — and thus
	// StreamEdges' first-wins dedup — is byte-identical to the sequential build.
	perAccount := make([]iamManipAccountResult, len(accts))
	workers := iamManipWorkers()
	if workers > len(accts) {
		workers = len(accts)
	}
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range accts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			perAccount[i] = iamManipAccountEdges(s, pe, accts[i], memo)
			// onItem advances a concurrency-safe progress counter (order-independent).
			if onItem != nil {
				onItem()
			}
		}(i)
	}
	wg.Wait()

	var out []*graph.Edge
	for _, result := range perAccount {
		out = append(out, result.composites...)
	}

	// Group-targeted base edges via the shared identity driver (§10): single-action
	// principal -> group scans, none consumed by the escalation composites.
	for _, spec := range []IdentitySpec{
		{Action: "iam:AddUserToGroup", Kind: graph.KindCanAddUserToGroup, TargetType: "group"},
		{Action: "iam:AttachGroupPolicy", Kind: graph.KindCanAttachGroupPolicy, TargetType: "group"},
		{Action: "iam:PutGroupPolicy", Kind: graph.KindCanPutGroupPolicy, TargetType: "group"},
		{Action: "iam:DeleteGroupPolicy", Kind: graph.KindCanDeleteGroupPolicy, TargetType: "group"},
		{Action: "iam:DetachGroupPolicy", Kind: graph.KindCanDetachGroupPolicy, TargetType: "group"},
		{Action: "iam:DeleteGroup", Kind: graph.KindCanDeleteGroup, TargetType: "group"},
		{Action: "iam:RemoveUserFromGroup", Kind: graph.KindCanRemoveUserFromGroup, TargetType: "group"},
		// User-targeted (free — not consumed by composites).
		{Action: "iam:DeleteUserPolicy", Kind: graph.KindCanDeleteUserPolicy, TargetType: "user"},
		{Action: "iam:DetachUserPolicy", Kind: graph.KindCanDetachUserPolicy, TargetType: "user"},
		{Action: "iam:DeleteUser", Kind: graph.KindCanDeleteUser, TargetType: "user"},
		{Action: "iam:PutUserPermissionsBoundary", Kind: graph.KindCanPutUserPermissionsBoundary, TargetType: "user"},
		{Action: "iam:DeleteUserPermissionsBoundary", Kind: graph.KindCanDeleteUserPermissionsBoundary, TargetType: "user"},
		// Role-targeted (free).
		{Action: "iam:DeleteRolePolicy", Kind: graph.KindCanDeleteRolePolicy, TargetType: "role"},
		{Action: "iam:DetachRolePolicy", Kind: graph.KindCanDetachRolePolicy, TargetType: "role"},
		{Action: "iam:PutRolePermissionsBoundary", Kind: graph.KindCanPutRolePermissionsBoundary, TargetType: "role"},
		{Action: "iam:DeleteRolePermissionsBoundary", Kind: graph.KindCanDeleteRolePermissionsBoundary, TargetType: "role"},
	} {
		out = append(out, GenerateIdentityGovernedEdges(s, pe, spec)...)
	}

	// Free wildcard-to-root primitives (CreateGroup + role-policy wildcards).
	out = append(out, GenerateResourceToRootEdges(s, pe, "iam:CreateGroup",
		func(id string) string { return "arn:aws:iam::" + id + ":group/*" }, graph.KindCanCreateGroup, "conditions")...)
	out = append(out, GenerateResourceToRootEdges(s, pe, "iam:AttachRolePolicy",
		func(id string) string { return "arn:aws:iam::" + id + ":role/*" }, graph.KindCanAttachRolePolicyWildcard, "conditions")...)
	out = append(out, GenerateResourceToRootEdges(s, pe, "iam:PutRolePolicy",
		func(id string) string { return "arn:aws:iam::" + id + ":role/*" }, graph.KindCanPutRolePolicyWildcard, "conditions")...)

	// SetDefaultPolicyVersion → customer-managed policies (driver with a
	// customer-policy candidate source).
	out = append(out, GenerateEdges(s, pe, EdgeSpec{
		Action: "iam:SetDefaultPolicyVersion", Kind: graph.KindCanSetDefaultPolicyVersion,
		Class: eval.IdentityGoverned, Candidates: iamManipCustomPolicyCandidates,
	})...)

	// Composite-consumed base edges were already evaluated while recording the
	// checks their composites require. Reuse those results instead of driving the
	// same principals×resources cross product a second time.
	for _, spec := range []IdentitySpec{
		{Action: "iam:AttachUserPolicy", Kind: graph.KindCanAttachUserPolicy, TargetType: "user"},
		{Action: "iam:PutUserPolicy", Kind: graph.KindCanPutUserPolicy, TargetType: "user"},
		{Action: "iam:AttachRolePolicy", Kind: graph.KindCanAttachRolePolicy, TargetType: "role"},
		{Action: "iam:PutRolePolicy", Kind: graph.KindCanPutRolePolicy, TargetType: "role"},
	} {
		for _, result := range perAccount {
			out = append(out, result.bases[spec.Kind]...)
		}
	}
	for _, result := range perAccount {
		out = append(out, result.bases[graph.KindCanCreatePolicyVersion]...)
	}
	for _, result := range perAccount {
		out = append(out, result.bases[graph.KindCanCreateUser]...)
	}
	return out
}

// iamManipCustomPolicyCandidates returns every account's customer-managed policy
// ARNs (AWS-managed policies are immutable, never targets), sorted.
func iamManipCustomPolicyCandidates(s *store.Store) []string {
	var out []string
	for _, a := range s.Accounts() {
		out = append(out, iamManipCustomManagedPolicies(a)...)
	}
	sort.Strings(out)
	return out
}

// iamManipCheck records the identity-policy evaluation behind one edge: the
// endpoints plus the raw allow-sources and condition list from the
// PermissionCheckResult. The composites aggregate these instead of re-parsing
// the string properties off already-built edges (which is what the Python
// EdgeView-based composites do via conditions_from / allow_sources.split).
type iamManipCheck struct {
	start      string
	end        string
	allowSrc   []string
	conditions []map[string]any
}

// iamManipPair is a (source, dest) control/re-permission key for the
// CanUpdateOtherPolicy composite.
type iamManipPair struct {
	source string
	dest   string
}

// iamManipState carries the per-account working set: the emitted edges plus the
// base-edge checks the composites consume.
type iamManipState struct {
	s      *store.Store
	pe     *eval.PolicyEvaluator
	acct   *store.Account
	root   string
	memo   *iamManipMemo
	edges  []*graph.Edge
	checks map[graph.EdgeKind][]iamManipCheck
	bases  map[graph.EdgeKind][]*graph.Edge
}

type iamManipAccountResult struct {
	composites []*graph.Edge
	bases      map[graph.EdgeKind][]*graph.Edge
}

// iamManipMemo is the action->principals pre-filter cache, shared across every
// account's iamManipState. The set is global (PrincipalsWithAction scans the whole
// principal universe, not one account), so it is memoised once per action and
// reused. It is concurrency-safe: iamManipulationEdges builds accounts in parallel
// and each computes principalsWith for the same handful of actions. Compute runs
// under the lock so each action's universe scan happens exactly once even under a
// cold cache and a full worker pool; the cached set is only ever read after
// creation (filteredCandidates/lookups never mutate it), so returning it unlocked
// is safe.
type iamManipMemo struct {
	s    *store.Store
	pe   *eval.PolicyEvaluator
	mu   sync.Mutex
	sets map[string]map[string]bool
}

func newIamManipMemo(s *store.Store, pe *eval.PolicyEvaluator) *iamManipMemo {
	return &iamManipMemo{s: s, pe: pe, sets: map[string]map[string]bool{}}
}

func (m *iamManipMemo) principalsWith(action string) map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set, ok := m.sets[action]; ok {
		return set
	}
	bm := m.pe.PrincipalsWithAction(action, "*")
	set := make(map[string]bool)
	for _, id := range bm.ToArray() {
		if arn := m.s.ARN().Arn(id); arn != "" {
			set[arn] = true
		}
	}
	m.sets[action] = set
	return set
}

// iamManipRecordedKinds are the base-edge kinds whose checks the composites
// need; only these are retained (the rest are emitted and forgotten).
var iamManipRecordedKinds = map[graph.EdgeKind]bool{
	graph.KindCanPutRolePolicy:       true,
	graph.KindCanAttachRolePolicy:    true,
	graph.KindCanPutUserPolicy:       true,
	graph.KindCanAttachUserPolicy:    true,
	graph.KindCanCreatePolicyVersion: true,
	graph.KindCanCreateUser:          true,
}

func iamManipAccountEdges(s *store.Store, pe *eval.PolicyEvaluator, acct *store.Account, memo *iamManipMemo) iamManipAccountResult {
	st := &iamManipState{
		s:      s,
		pe:     pe,
		acct:   acct,
		root:   "arn:aws:iam::" + acct.ID + ":root",
		memo:   memo,
		checks: map[graph.EdgeKind][]iamManipCheck{},
		bases:  map[graph.EdgeKind][]*graph.Edge{},
	}

	groups := sortedKeys(acct.Groups)
	users := sortedKeys(acct.Users)
	roles := sortedKeys(acct.Roles)
	customPolicies := iamManipCustomManagedPolicies(acct)
	customSet := make(map[string]bool, len(customPolicies))
	for _, p := range customPolicies {
		customSet[p] = true
	}

	// Group-targeted primitives (principal -> group) are generated globally via the
	// shared identity driver in IAMManipulationEdges (none are consumed by the
	// escalation composites, so they need no recording here).
	_ = groups

	// -- Composite-consumed base kinds (Attach*/Put*Policy, CreatePolicyVersion —
	// see iamManipRecordedKinds). Their base EDGES are now generated by the driver
	// in IAMManipulationEdges; here we only RECORD their checks so the escalation
	// composites (which read st.checks) still see them. --
	st.recordMulti("iam:AttachUserPolicy", graph.KindCanAttachUserPolicy, users)
	st.recordMulti("iam:PutUserPolicy", graph.KindCanPutUserPolicy, users)
	st.recordMulti("iam:AttachRolePolicy", graph.KindCanAttachRolePolicy, roles)
	st.recordMulti("iam:PutRolePolicy", graph.KindCanPutRolePolicy, roles)
	st.recordMulti("iam:CreatePolicyVersion", graph.KindCanCreatePolicyVersion, customPolicies)

	// -- Wildcard-resource primitives (principal -> account root). The resource
	// is a not-yet-created wildcard, so candidates are ALL principals: the
	// interned-target pre-filter would wrongly drop a grant on an empty
	// name-space (e.g. iam:CreateUser on user/* in an account with no users). --
	acctPrefix := "arn:aws:iam::" + acct.ID + ":"
	// CreateUser is composite-recorded — record its check only; the base edge is
	// generated by the driver. (CreateGroup + role-policy wildcards were already
	// driver-migrated.)
	st.recordWildcard("iam:CreateUser", graph.KindCanCreateUser, acctPrefix+"user/*")

	// -- Escalation composites (principal -> account root, traversable). --
	iamManipUpdateSelfPolicy(st, customSet)
	iamManipUpdateOtherPolicy(st, customSet)
	iamManipCreateAndAccessAdminUser(st)

	return iamManipAccountResult{composites: st.edges, bases: st.bases}
}

func (st *iamManipState) emit(e *graph.Edge) { st.edges = append(st.edges, e) }

func (st *iamManipState) record(kind graph.EdgeKind, c iamManipCheck) {
	if iamManipRecordedKinds[kind] {
		st.checks[kind] = append(st.checks[kind], c)
	}
}

// principalsWith returns the set of principal ARNs (users + roles, any account)
// whose identity policies grant action against at least one interned resource —
// the Go equivalent of policy_evaluator.principals_with_action used as the cheap
// pre-filter. Memoised across accounts. Safe as a pre-filter ONLY for real
// interned targets: any principal it drops has no allow statement that could
// match an interned resource, so CanPerformAction on an interned target would
// deny it anyway.
func (st *iamManipState) principalsWith(action string) map[string]bool {
	return st.memo.principalsWith(action)
}

// multiTarget emits `principal -> target` edges for every candidate principal
// (pre-filtered to those referencing action) that is allowed action on each
// target. Ports SimpleActionEdgeProcessor / the equivalent BaseEdgeProcessor
// bodies (CanAttachRolePolicy, CanDeleteRolePermissionsBoundary).
func (st *iamManipState) multiTarget(action string, kind graph.EdgeKind, targets []string) {
	if len(targets) == 0 {
		return
	}
	cands := filteredCandidates(st.acct, st.principalsWith(action))
	for _, p := range cands {
		for _, t := range targets {
			res := st.pe.CanPerformAction(p, action, t, nil)
			if !res.Allowed {
				continue
			}
			st.emit(permissionEdge(p, t, kind, false, res))
			st.record(kind, iamManipCheck{start: p, end: t, allowSrc: res.AllowSources, conditions: res.Conditions})
		}
	}
}

// wildcardToRoot emits `principal -> account root` edges for every principal
// allowed action on a wildcard resource. Ports WildcardRoleActionEdgeProcessor
// and CanCreateUser / CanCreateGroup. Candidates are all principals (see caller
// comment).
func (st *iamManipState) wildcardToRoot(action string, kind graph.EdgeKind, resource string) {
	for _, p := range principalARNs(st.acct) {
		res := st.pe.CanPerformAction(p, action, resource, nil)
		if !res.Allowed {
			continue
		}
		st.emit(permissionEdge(p, st.root, kind, false, res))
		st.record(kind, iamManipCheck{start: p, end: st.root, allowSrc: res.AllowSources, conditions: res.Conditions})
	}
}

// recordMulti records the checks for a composite-consumed multiTarget kind and
// builds its base edges at the same time. The escalation composites read
// st.checks, while IAMManipulationEdges later emits the retained base edges.
func (st *iamManipState) recordMulti(action string, kind graph.EdgeKind, targets []string) {
	cands := filteredCandidates(st.acct, st.principalsWith(action))
	for _, p := range cands {
		for _, t := range targets {
			res := st.pe.CanPerformAction(p, action, t, nil)
			if res.Allowed {
				st.record(kind, iamManipCheck{start: p, end: t, allowSrc: res.AllowSources, conditions: res.Conditions})
				st.bases[kind] = append(st.bases[kind], permissionEdge(p, t, kind, false, res))
			}
		}
	}
}

// recordWildcard is recordMulti for a wildcard-to-root kind (end == account root).
func (st *iamManipState) recordWildcard(action string, kind graph.EdgeKind, resource string) {
	for _, p := range principalARNs(st.acct) {
		res := st.pe.CanPerformAction(p, action, resource, nil)
		if res.Allowed {
			st.record(kind, iamManipCheck{start: p, end: st.root, allowSrc: res.AllowSources, conditions: res.Conditions})
			st.bases[kind] = append(st.bases[kind], permissionEdge(p, st.root, kind, false, res))
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// iamManipCandidates-related helpers.

// iamManipCustomManagedPolicies returns the account's customer-managed policy
// ARNs (sorted), excluding AWS-managed policies — get_custom_managed_policy_arns.
func iamManipCustomManagedPolicies(acct *store.Account) []string {
	var out []string
	for _, arn := range sortedKeys(acct.ManagedPolicies) {
		if !iamManipIsAWSManaged(arn) {
			out = append(out, arn)
		}
	}
	return out
}

// iamManipIsAWSManaged reports whether a policy ARN belongs to AWS's shared
// managed-policy account. Mirrors _row_helpers._is_aws_managed.
func iamManipIsAWSManaged(arn string) bool {
	return strings.HasPrefix(arn, "arn:aws:iam::aws:") ||
		strings.HasPrefix(arn, "arn:aws-cn:iam::aws:") ||
		strings.HasPrefix(arn, "arn:aws-us-gov:iam::aws:")
}
