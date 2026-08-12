// This file ports the CloudFormation attack-path family
// (core/graph/edges/cloudformation/) into Go. It emits the FIVE wave-0 primitive
// edges the IAM policy evaluator grants a principal over CloudFormation stacks and
// StackSets:
//
//	CanCreateCloudFormationStack      AWS_CanCreateCloudFormationStack      cloudformation:CreateStack       -> account root  (non-traversable)
//	CanCreateCloudFormationStackSet   AWS_CanCreateCloudFormationStackSet   cloudformation:CreateStackSet    -> account root  (non-traversable)
//	CanUpdateCloudFormationStack      AWS_CanUpdateCloudFormationStack      cloudformation:UpdateStack       -> stack         (TRAVERSABLE)
//	CanUpdateCloudFormationStackSet   AWS_CanUpdateCloudFormationStackSet   cloudformation:UpdateStackSet    -> StackSet      (non-traversable)
//	CanExecuteCloudFormationChangeSet AWS_CanExecuteCloudFormationChangeSet cloudformation:CreateChangeSet
//	                                                                        + cloudformation:ExecuteChangeSet -> stack        (TRAVERSABLE)
//
// NOT emitted here — the four Python pass-role / create-and-pass processors in the
// same directory (PassRoleViaCloudFormation, PassRoleViaCloudFormationStackSet,
// PassRoleViaCloudFormationStackSetUpdate, CanCreateAndPassCloudFormationAdminRole)
// are non-traversable CONSTITUENTS that AWSHound folds into — and then SUPPRESSES
// beneath — the merged AWS_CanPassRoleToService / AWS_CanCreateAndPassAdminRole
// edges. The Go schema has no constituent edge kinds for them (only the merged
// kinds exist in graph/kinds.go), and the role_trust_and_federation family's
// role_trust_meta.go already recomputes every CloudFormation pass-role constituent
// inline (CreateStack, CreateStackSet+CreateStackInstances, UpdateStackSet, and
// UpdateStack for CanPassRoleToService; CreateStack for CanCreateAndPassAdminRole)
// and emits the merged edges. Emitting them here would either reference a
// non-existent kind or double the merged edges, so this family stops at the five
// primitives — exactly the CloudFormation edge kinds the Go schema defines.
//
// Fidelity notes:
//   - Per-account scope: principals and resources share one account id, so a
//     principal is only ever checked against stacks / StackSets in its own account.
//     Principals are users + roles only — get_all_principal_arns excludes groups.
//   - CreateStack / CreateStackSet are account-scoped (Resource:"*" is the only
//     valid form): evaluated against "*" and pointed at arn:aws:iam::<acct>:root.
//     CanPerformAction("*") matches only a universal-resource grant, so a narrowly
//     scoped grant produces no edge — exactly as in Python. The Python
//     CreateStack / CreateStackSet processors additionally run a
//     principals_with_action pre-filter, but that is a pure optimization (it can
//     only drop principals whose allow index lacks the action, which
//     CanPerformAction rejects anyway), so looping every principal is identical.
//   - UpdateStack / UpdateStackSet / ExecuteChangeSet are resource-scoped: evaluated
//     against each COLLECTED stack / StackSet ARN, never "*" — so a principal
//     holding the action with no stack/StackSet present produces no edge. The edge
//     is emitted per matching stack/StackSet regardless of whether the stack has a
//     RoleARN (the RunsAs continuation is a separate structural edge).
//   - ExecuteChangeSet requires BOTH cloudformation:CreateChangeSet AND
//     cloudformation:ExecuteChangeSet on the stack (create stages, execute applies);
//     it short-circuits on the first denial. Its `allow_sources` is the
//     order-preserving, empty-skipping dedup union of the two grants' sources; its
//     `conditions` is the two grants' condition lists concatenated (NOT deduped).
//   - Condition properties carry the evaluator's condition list as a JSON string,
//     "" when there are none. The create primitives and UpdateStackSet name the
//     property `service_action_conditions`; UpdateStack and ExecuteChangeSet name it
//     `conditions` — matching each Python processor's Properties(...) exactly.
//   - Property insertion order per edge matches the Python Properties(...) kwargs
//     order (a Python dict preserves kwarg order), so the emitted JSON is stable.
//   - JSON conditions use compact json.Marshal (no separators), the package
//     convention established by iam_manipulation.go / ssm.go / role_trust.go.
//   - The final edge slice is sorted by (start, end, kind) for diff-stable output.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// CloudFormationEdges emits the CloudFormation family's five wave-0 primitive edges
// for the whole store, scoped per account (a principal is only checked against
// stacks / StackSets in its own account), then sorts the combined slice for stable
// output.
func CloudFormationEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	if s == nil || pe == nil {
		return nil
	}

	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })

	var out []*graph.Edge
	for _, a := range accounts {
		out = append(out, cloudformationAccountEdges(a, pe)...)
	}

	// UpdateStack (→ stack, traversable, "conditions") and UpdateStackSet
	// (→ stackset, non-traversable, "service_action_conditions") via the driver (§10).
	out = append(out, GenerateIdentityGovernedEdges(s, pe, IdentitySpec{
		Action: "cloudformation:UpdateStack", Kind: graph.KindCanUpdateCloudFormationStack,
		TargetType: "stack", Traversable: true,
	})...)
	out = append(out, GenerateEdges(s, pe, EdgeSpec{
		Action: "cloudformation:UpdateStackSet", Kind: graph.KindCanUpdateCloudFormationStackSet,
		TargetType: "stackset", Class: eval.IdentityGoverned, CondKey: "service_action_conditions",
	})...)
	// Account-scoped create primitives (→ account root, service_action_conditions).
	out = append(out, GenerateAccountScopedEdges(s, pe, "cloudformation:CreateStack", graph.KindCanCreateCloudFormationStack, "service_action_conditions")...)
	out = append(out, GenerateAccountScopedEdges(s, pe, "cloudformation:CreateStackSet", graph.KindCanCreateCloudFormationStackSet, "service_action_conditions")...)

	// ExecuteChangeSet: 2-action composite (CreateChangeSet AND ExecuteChangeSet on a
	// stack) via the composite driver; the bespoke per-action property split is built
	// by the edge callback.
	out = append(out, GenerateCompositeEdges(s, pe,
		[]string{"cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"},
		cloudformationStackCandidates, false,
		func(principal, stackARN string, r []*eval.PermissionCheckResult) *graph.Edge {
			create, execute := r[0], r[1]
			e := graph.NewEdge(principal, stackARN, graph.KindCanExecuteCloudFormationChangeSet)
			e.Set("is_traversable", true)
			e.Set("create_change_set_allow_sources", strings.Join(create.AllowSources, ", "))
			e.Set("execute_change_set_allow_sources", strings.Join(execute.AllowSources, ", "))
			e.Set("allow_sources", strings.Join(cloudformationDedupSources(create.AllowSources, execute.AllowSources), ", "))
			e.Set("conditions", conditionsJSON(cloudformationConcatConditions(create.Conditions, execute.Conditions)))
			return e
		})...)

	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return string(out[i].Kind) < string(out[j].Kind)
	})
	return out
}

// cloudformationAccountEdges emits every CloudFormation edge one account earns. For
// each of the account's principals (users + roles) it evaluates the two
// account-scoped create primitives against "*", the resource-scoped UpdateStack and
// ExecuteChangeSet primitives against each collected stack, and the resource-scoped
// UpdateStackSet primitive against each collected StackSet.
// cloudformationStackCandidates returns every account's stack ARNs, sorted.
func cloudformationStackCandidates(s *store.Store) []string {
	var out []string
	for _, a := range s.Accounts() {
		out = append(out, stackARNs(a)...)
	}
	sort.Strings(out)
	return out
}

func cloudformationAccountEdges(a *store.Account, pe *eval.PolicyEvaluator) []*graph.Edge {
	principals := principalARNs(a)
	if len(principals) == 0 {
		return nil
	}

	// All cloudformation edges are now generated globally via the driver in
	// CloudFormationEdges (account-scoped creates, UpdateStack/UpdateStackSet, and
	// the change-set composite); this per-account helper is empty.
	_ = principals
	return nil
}

// cloudformationChangeSetEdge ports CanExecuteCloudFormationChangeSetEdgeProcessor:
// a principal that can BOTH cloudformation:CreateChangeSet AND
// cloudformation:ExecuteChangeSet on a stack can stage a rewritten template and
// apply it, executing as the stack's RoleARN with no iam:PassRole. Both actions are
// required — it short-circuits on the first denial (create stages; execute applies).
// Returns nil when either action is denied.
func cloudformationChangeSetEdge(pe *eval.PolicyEvaluator, principal, stackARN string) *graph.Edge {
	create := pe.CanPerformAction(principal, "cloudformation:CreateChangeSet", stackARN, nil)
	if !create.Allowed {
		return nil
	}
	execute := pe.CanPerformAction(principal, "cloudformation:ExecuteChangeSet", stackARN, nil)
	if !execute.Allowed {
		return nil
	}
	e := graph.NewEdge(principal, stackARN, graph.KindCanExecuteCloudFormationChangeSet)
	e.Set("is_traversable", true)
	e.Set("create_change_set_allow_sources", strings.Join(create.AllowSources, ", "))
	e.Set("execute_change_set_allow_sources", strings.Join(execute.AllowSources, ", "))
	e.Set("allow_sources", strings.Join(cloudformationDedupSources(create.AllowSources, execute.AllowSources), ", "))
	e.Set("conditions", conditionsJSON(cloudformationConcatConditions(create.Conditions, execute.Conditions)))
	return e
}

// cloudformationPrimitiveEdge builds a single-grant CloudFormation primitive edge
// with the (is_traversable, allow_sources, <condKey>) property set, in that
// insertion order. condKey is the Python processor's condition property name:
// `service_action_conditions` for the account-scoped create primitives and
// UpdateStackSet, `conditions` for UpdateStack.
func cloudformationPrimitiveEdge(start, end string, kind graph.EdgeKind, traversable bool, condKey string, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, end, kind)
	e.Set("is_traversable", traversable)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set(condKey, conditionsJSON(res.Conditions))
	return e
}

// cloudformationDedupSources returns the order-preserving union of two allow-source
// lists, skipping empty strings and duplicates (create sources first, then execute)
// — the change-set processor's combined `allow_sources`, matching the Python
// `for src in [*create.allow_sources, *execute.allow_sources]: if src and src not in
// out: out.append(src)`.
func cloudformationDedupSources(create, execute []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, src := range create {
		if src != "" && !seen[src] {
			seen[src] = true
			out = append(out, src)
		}
	}
	for _, src := range execute {
		if src != "" && !seen[src] {
			seen[src] = true
			out = append(out, src)
		}
	}
	return out
}

// cloudformationConcatConditions returns the two condition lists concatenated
// (create first), or nil when both are empty — the change-set processor's combined
// `conditions` payload (concatenated, NOT deduped, matching the Python
// [*create.conditions, *execute.conditions]). A fresh slice is built so neither
// evaluator result's condition slice is aliased or mutated.
func cloudformationConcatConditions(create, execute []map[string]any) []map[string]any {
	if len(create) == 0 && len(execute) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(create)+len(execute))
	out = append(out, create...)
	out = append(out, execute...)
	return out
}
