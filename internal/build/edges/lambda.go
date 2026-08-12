// This file ports the Lambda attack-path family (core/graph/edges/awslambda/) plus
// the Lambda Function Write/All meta edges (core/graph/edges/meta/, see
// lambda_meta.go). It emits principal -> {function, account} edges for every Lambda
// capability the IAM policy evaluator grants, then consolidates the function-scoped
// constituents into the two Lambda meta edges.
//
// Scope. All the function-scoped constituents EXCEPT InvokeFunction are WITHIN an
// account: each Python processor runs per account with
// get_all_principal_arns(account) x get_lambda_function_arns(account), so a
// principal only earns those edges to a function in its OWN account. This port
// preserves that by iterating each account's functions for those constituents.
// InvokeFunction is the exception: its Python processor deliberately iterates
// get_lambda_function_arns() over EVERY account (a Lambda resource policy can grant
// lambda:InvokeFunction cross-account, mirroring how the S3 processors iterate all
// bucket ARNs), so this port evaluates invoke against the global function set.
// Principals are users + roles only (get_all_principal_arns), never groups.
//
// Invoke branch fidelity. The Python CanInvokeLambdaFunction processor has two
// evaluation paths: a LambdaResourcePolicyEvaluator path (IAM + function resource
// policy) when a lambda_evaluator is supplied via context, and an IAM-only fallback
// (policy_evaluator.can_perform_action) otherwise. This port builds an
// eval.LambdaEvaluator from every account's function resource policies (fn.Policy,
// the raw GetPolicy document, parsed as PLAIN JSON via eval.ParseResourcePolicy)
// and gates invoke through EvaluateLambdaResourcePolicy: an invoke granted solely
// by a wildcard/account-root resource policy (no IAM) is emitted, and a
// cross-account invoke correctly requires IAM AND the resource policy. Matching
// runtime.contexts.build_lambda_context, the evaluator is built only when at least
// one function carries a resource policy; with none, invoke stays on the IAM-only
// fallback (CanPerformAction). Edge allow_sources/conditions come from the active
// path (on the composed path the labels "iam_policy" / "resource_policy").
//
// CanCreateLambdaFunction is the one account-scoped primitive: lambda:CreateFunction
// is evaluated on resource "*" and the edge points principal -> account root
// (matching the Python wave-0 primitive and the EC2 RunInstances convention). It is
// materialised here because it survives in the Python graph (the composites consume
// it but never suppress it); its action conditions live on service_action_conditions.
//
// Not emitted here: AWS_CanPassRoleViaLambda and AWS_CanCreateAndPassLambdaAdminRole.
// The Go schema has no per-service kinds for those — they are folded into the merged
// AWS_CanPassRoleToService / AWS_CanCreateAndPassAdminRole edges, which the
// role_trust family owns and recomputes inline (see role_trust_meta.go, which reads
// lambda:CreateFunction / lambda:UpdateFunctionConfiguration off the store+evaluator
// directly). Emitting them here would double them.
//
// Endpoints carry raw ARNs (the colon->underscore id encoding is a terminal concern
// of the emit package); the function ARN comes from the store and the account-root
// ARN is synthesized identically to the IAM node builder so every edge connects to a
// real node. The final edge slice is sorted by (start, end, kind) for diff-stable
// output.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// lambdaFuncScopedSpec binds one single-action, function-scoped Lambda action to its
// edge kind and is_traversable flag. It captures the shape shared by the simplest
// Lambda processors: for each principal, for each function in the account, emit
// principal -> function when CanPerformAction(action, functionArn) is allowed.
type lambdaFuncScopedSpec struct {
	action      string
	kind        graph.EdgeKind
	traversable bool
}

// lambdaSimpleSpecs are the single-action, account-scoped function constituents that
// share the identical shape. UpdateFunctionCode and UpdateFunctionConfiguration are
// traversable (each lets an attacker run code under the function's execution role);
// the AddPermission/RemovePermission/DeleteFunction/CreateEventSourceMapping edges
// are non-traversable capability edges. CanUpdateLambdaUrlConfig (two candidate
// actions) and CanInvokeLambdaFunction (cross-account) are shaped differently and
// handled separately below.
var lambdaSimpleSpecs = []lambdaFuncScopedSpec{
	{"lambda:UpdateFunctionCode", graph.KindCanUpdateLambdaCode, true},
	{"lambda:UpdateFunctionConfiguration", graph.KindCanUpdateLambdaConfiguration, true},
	{"lambda:AddPermission", graph.KindCanAddLambdaPermission, false},
	{"lambda:RemovePermission", graph.KindCanRemoveLambdaPermission, false},
	{"lambda:DeleteFunction", graph.KindCanDeleteLambdaFunction, false},
	{"lambda:CreateEventSourceMapping", graph.KindCanCreateLambdaEventSource, false},
}

// LambdaSimpleSpecs exposes the six account-scoped, function-scoped Lambda
// constituents as generic identity-governed edge specs (§10). The union invoke,
// URL-config fall-through, account-scoped CreateFunction, and meta edges are
// shaped differently and remain specialized in LambdaEdges.
func LambdaSimpleSpecs() []IdentitySpec {
	out := make([]IdentitySpec, 0, len(lambdaSimpleSpecs))
	for _, sp := range lambdaSimpleSpecs {
		out = append(out, IdentitySpec{
			Action: sp.action, Kind: sp.kind, TargetType: "function", Traversable: sp.traversable,
		})
	}
	return out
}

// LambdaEdges emits the Lambda family's attack-path edges for the whole store: the
// per-permission constituents (invoke, update code/configuration/url-config,
// add/remove permission, create event source, delete, create function) and the
// LambdaFunction Write/All meta edges consolidated from the function-scoped ones.
func LambdaEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })

	// Global function set for the cross-account InvokeFunction check. Deduplicated +
	// sorted for stable evaluation order and output. The same sweep collects each
	// function's resource policy (fn.Policy, the raw GetPolicy JSON, parsed as PLAIN
	// JSON via eval.ParseResourcePolicy) keyed by function ARN, so invoke can be
	// composed against resource policies in every account — mirroring
	// runtime.contexts.build_lambda_context.
	var allFunctions []string
	seen := make(map[string]bool)
	functionResourcePolicies := make(map[string]*eval.Policy)
	for _, a := range accounts {
		for _, fn := range a.LambdaFunctionList() {
			if fn.FunctionArn == "" || seen[fn.FunctionArn] {
				continue
			}
			seen[fn.FunctionArn] = true
			allFunctions = append(allFunctions, fn.FunctionArn)
			if fn.Policy == "" {
				continue
			}
			if pol, err := eval.ParseResourcePolicy([]byte(fn.Policy)); err == nil && pol != nil {
				functionResourcePolicies[fn.FunctionArn] = pol
			}
		}
	}
	sort.Strings(allFunctions)

	// The Lambda evaluator composes IAM with the function resource policies (identity
	// side wrapped via iamIdentity). Built only when at least one function carries a
	// resource policy: build_lambda_context supplies no lambda_evaluator otherwise,
	// leaving the invoke processor on its IAM-only fallback (which is what le == nil
	// selects below).
	var le *eval.LambdaEvaluator
	if len(functionResourcePolicies) > 0 {
		le = eval.NewLambdaEvaluator(iamIdentity(pe), functionResourcePolicies, pe.ResourcePolicyContext)
	}

	// Wave 0 — the per-permission constituent edges.
	var constituents []*graph.Edge

	// URL config: fall-through (CreateFunctionUrlConfig OR UpdateFunctionUrlConfig)
	// per function, account-scoped, via the scan driver's EvalFunc.
	constituents = append(constituents, GenerateScanEdges(s, ScanSpec{
		Kind:       graph.KindCanUpdateLambdaURLConfig,
		Candidates: func(*store.Store) []string { return allFunctions },
		Eval: func(principal, fnArn string) EvalResult {
			res := pe.CanPerformAction(principal, "lambda:CreateFunctionUrlConfig", fnArn, nil)
			if !res.Allowed {
				res = pe.CanPerformAction(principal, "lambda:UpdateFunctionUrlConfig", fnArn, nil)
			}
			return EvalResult{Allowed: res.Allowed, AllowSources: res.AllowSources, Conditions: res.Conditions}
		},
	})...)

	// CreateFunction: account-scoped (resource "*") → account root, service_action_conditions.
	constituents = append(constituents, GenerateAccountScopedEdges(s, pe, "lambda:CreateFunction", graph.KindCanCreateLambdaFunction, "service_action_conditions")...)

	// Invoke: cross-account union, generated through the scan driver (global
	// principals × every function). Composed through the Lambda evaluator when any
	// function carries a resource policy; otherwise IAM-only — identical to the
	// removed inline loop.
	constituents = append(constituents, GenerateScanEdges(s, ScanSpec{
		Kind: graph.KindCanInvokeLambdaFunction, Traversable: false,
		Candidates:       func(*store.Store) []string { return allFunctions },
		GlobalPrincipals: true,
		Eval: func(principal, fnArn string) EvalResult {
			if le != nil {
				r := le.EvaluateLambdaResourcePolicy(principal, fnArn)
				return EvalResult{Allowed: r.Allowed, AllowSources: r.AllowSources, Conditions: r.Conditions}
			}
			r := pe.CanPerformAction(principal, "lambda:InvokeFunction", fnArn, nil)
			return EvalResult{Allowed: r.Allowed, AllowSources: r.AllowSources, Conditions: r.Conditions}
		},
	})...)

	// The six account-scoped, function-scoped constituents are generated through
	// the shared spec driver (§10) — identical edges to the removed inline loop,
	// feeding the same meta consolidation below (which is set-based, so generation
	// order is irrelevant).
	for _, spec := range LambdaSimpleSpecs() {
		constituents = append(constituents, GenerateIdentityGovernedEdges(s, pe, spec)...)
	}

	// Waves 1-2 — meta edges (LambdaFunctionAll, then LambdaFunctionWrite) +
	// suppression of the function-scoped constituents they consume.
	out := lambdaApplyMetaWaves(constituents)

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

// lambdaConstituentEdge builds a per-permission, function-scoped Lambda edge. Ported
// from the single-action Lambda processors' Properties(is_traversable=...,
// allow_sources=", ".join(...), conditions=json.dumps(...) or ""). Property
// insertion order is is_traversable, allow_sources, conditions.
func lambdaConstituentEdge(start, end string, kind graph.EdgeKind, traversable bool, allowSources []string, conditions []map[string]any) *graph.Edge {
	e := graph.NewEdge(start, end, kind)
	e.Set("is_traversable", traversable)
	e.Set("allow_sources", strings.Join(allowSources, ", "))
	e.Set("conditions", conditionsJSON(conditions))
	return e
}

// lambdaCreateFunctionEdge builds the AWS_CanCreateLambdaFunction wave-0 primitive
// (principal -> account root, non-traversable). lambda:CreateFunction is
// account-scoped (evaluated on resource "*"), so the end node is the account root,
// matching the Python CanCreateLambdaFunctionEdgeProcessor. Its action conditions are
// carried on service_action_conditions (NOT conditions) so the pass-role /
// create-and-pass composites can read them; property insertion order is
// is_traversable, allow_sources, service_action_conditions.
func lambdaCreateFunctionEdge(start, accountRoot string, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, accountRoot, graph.KindCanCreateLambdaFunction)
	e.Set("is_traversable", false)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set("service_action_conditions", conditionsJSON(res.Conditions))
	return e
}
