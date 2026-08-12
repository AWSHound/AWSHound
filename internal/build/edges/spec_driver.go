// This file is the generic, declarative edge driver of the authorization-tensor
// design (docs/authorization-tensor.md §10). Instead of ~20 hand-written per-family
// resource scans, a family is described by an IdentitySpec, and the driver produces
// its edges by: type-filtering candidate resources to the spec's target type,
// crossing each resource with its account's principals, evaluating the identity
// side through the eval.Factor algebra, and composing per resource class. Edge
// properties (allow_sources, conditions) come from the per-survivor
// PermissionCheckResult — the sparse query-time overlay of §5.5.
package edges

import (
	"sort"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// ResourceFactorFunc produces the resource-side admit Factor for one resource over
// the given candidate principals — the pluggable strategy of §5.4/§7. A nil func
// means the resource contributes nothing of its own (identity-governed class).
type ResourceFactorFunc func(s *store.Store, pe *eval.PolicyEvaluator, resourceArn string, principals []string) eval.Factor

// EdgeSpec declares one edge family: the IAM action that gates it, the edge kind,
// the resource type it targets, whether the edge is traversable, the resource
// class governing identity⊕resource composition, and (for non-identity-governed
// classes) the resource-side factor strategy.
type EdgeSpec struct {
	Action      string
	Kind        graph.EdgeKind
	TargetType  string
	Traversable bool
	Class       eval.ResourceClass
	Resource    ResourceFactorFunc
	// Candidates optionally overrides where target resources come from. By default
	// they are the interned ARNs of TargetType (the type-tagged universe). Types
	// evicted from the universe for memory (§4 — S3 objects, EC2 instances) supply
	// a source that enumerates them from the account resource bag instead.
	Candidates func(*store.Store) []string
	// CondKey overrides the conditions property key (default "conditions"). Some
	// primitives use "service_action_conditions" so downstream composites can read
	// their conditions.
	CondKey string
}

// IdentitySpec declares one identity-governed edge family — the common case with
// no resource-side strategy. It is EdgeSpec specialized to eval.IdentityGoverned.
type IdentitySpec struct {
	Action      string
	Kind        graph.EdgeKind
	TargetType  string
	Traversable bool
}

// GenerateIdentityGovernedEdges emits the edges for an identity-governed spec: no
// resource policy, composition is identity ∧ same-account.
func GenerateIdentityGovernedEdges(s *store.Store, pe *eval.PolicyEvaluator, spec IdentitySpec) []*graph.Edge {
	return GenerateEdges(s, pe, EdgeSpec{
		Action: spec.Action, Kind: spec.Kind, TargetType: spec.TargetType,
		Traversable: spec.Traversable, Class: eval.IdentityGoverned,
	})
}

// GenerateEdges emits the edges for any spec. Candidate resources are exactly the
// interned ARNs of the spec's target type (the §7 type filter); each is crossed
// with its own account's principals (users + roles), the identity side is
// evaluated into an eval.Factor, the resource side (if any) into another, and the
// two are composed under the spec's resource class. One edge is emitted per
// allowed principal; properties come from the per-survivor PermissionCheckResult.
// The result is sorted by (start, end, kind) for diff-stable output.
func GenerateEdges(s *store.Store, pe *eval.PolicyEvaluator, spec EdgeSpec) []*graph.Edge {
	resources := sortedARNsOfType(s, spec.TargetType)
	if spec.Candidates != nil {
		resources = spec.Candidates(s)
	}
	// Candidate pre-filter: for classes where an identity allow is mandatory
	// (IdentityGoverned: allowed = identity ∩ same-account; MandatoryPolicy:
	// allowed = identity ∩ resource), a principal with no effective identity allow
	// for spec.Action can never be in the composed Allowed set, so skip evaluating
	// it entirely. This mirrors the Python edge processors' principals_with_action
	// pre-filter and collapses the principals×resources cross product to the
	// (usually tiny) set of principals that actually hold the action. OptionalUnion
	// is intentionally exempt — a resource policy alone can grant there, so identity
	// absence does not preclude an edge. See eval.Compose.
	//
	// The pre-filter set is PrincipalsWithActionAll = principals whose allow could
	// match some INTERNED resource, so it is a valid superset only when the targets
	// are themselves interned — i.e. the default TargetType universe (spec.Candidates
	// == nil). A custom Candidates source may enumerate resources evicted from the
	// universe (EC2 instances, S3 objects, SSM instances — §4); a grant scoped to
	// one of those specific ARNs resolves to no interned id and so is absent from the
	// pre-filter set, which would wrongly drop the edge. For those specs, evaluate
	// every principal (unfiltered).
	var actionPrincipals *roaring.Bitmap
	if spec.Candidates == nil && (spec.Class == eval.IdentityGoverned || spec.Class == eval.MandatoryPolicy) {
		actionPrincipals = pe.PrincipalsWithActionAll(spec.Action)
	}
	var out []*graph.Edge
	for _, res := range resources {
		acctID := edgeAccountOf(res)
		if acctID == "" {
			continue
		}
		principals := principalARNs(s.Account(acctID))
		if actionPrincipals != nil {
			principals = filterPrincipalsByBitmap(s, principals, actionPrincipals)
		}
		if len(principals) == 0 {
			continue
		}
		identity := pe.IdentityFactor(spec.Action, res, principals).Resolve(eval.AttackerBias)
		resource := eval.Decision{}
		if spec.Resource != nil {
			resource = spec.Resource(s, pe, res, principals).Resolve(eval.AttackerBias)
		}
		decision := eval.Compose(identity, resource, spec.Class, principalIDMask(s, principals))
		for _, id := range decision.Allowed.ToArray() {
			p := s.ARN().Arn(id)
			// Fetch the per-principal result for edge properties (the query-time
			// overlay); it re-confirms the allow the factor already established.
			r := pe.CanPerformAction(p, spec.Action, res, nil)
			if !r.Allowed {
				continue
			}
			if spec.CondKey == "" || spec.CondKey == "conditions" {
				out = append(out, permissionEdge(p, res, spec.Kind, spec.Traversable, r))
			} else {
				e := graph.NewEdge(p, res, spec.Kind)
				e.Set("is_traversable", spec.Traversable)
				e.Set("allow_sources", strings.Join(r.AllowSources, ", "))
				e.Set(spec.CondKey, conditionsJSON(r.Conditions))
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// EvalResult is the outcome of evaluating one (principal, resource) pair for a
// scan-based family: whether an edge exists and the allow_sources / conditions to
// carry on it (the union/gated evaluator's result).
type EvalResult struct {
	Allowed      bool
	AllowSources []string
	Conditions   []map[string]any
}

// EvalFunc evaluates one (principal, resource) pair. Union families (S3, KMS,
// Lambda invoke) supply one wrapping their resource evaluator so the combined
// identity+resource decision and its provenance drive the edge.
type EvalFunc func(principal, resource string) EvalResult

// ScanSpec declares a scan-based edge family — the general form for union and
// gated processors that don't reduce to the pure identity factor. Every candidate
// resource is crossed with the principal set (global for cross-account union,
// else the resource's own account) and evaluated through Eval; one edge is emitted
// per allow, carrying (is_traversable, allow_sources, conditions) in that order —
// identical to permissionEdge.
type ScanSpec struct {
	Kind             graph.EdgeKind
	Traversable      bool
	Candidates       func(*store.Store) []string
	GlobalPrincipals bool
	Eval             EvalFunc
	// OmitTraversable drops the is_traversable property entirely (the S3
	// constituents carry only allow_sources + conditions, unlike KMS/Lambda which
	// lead with is_traversable).
	OmitTraversable bool
	// EdgeFn, if set, builds the edge from the (principal, resource, result) — for
	// scans whose edge carries extra properties (e.g. kms self-grant's
	// grantable_operations). Overrides the default (is_traversable, allow_sources,
	// conditions) builder.
	EdgeFn func(principal, resource string, r EvalResult) *graph.Edge
}

// GenerateScanEdges runs a scan-based spec. Results are NOT sorted here (callers
// that need stable order sort the combined family output), matching how the
// hand-written union families accumulate then sort.
func GenerateScanEdges(s *store.Store, spec ScanSpec) []*graph.Edge {
	var global []string
	if spec.GlobalPrincipals {
		global = allPrincipals(s)
	}
	var out []*graph.Edge
	for _, res := range spec.Candidates(s) {
		principals := global
		if !spec.GlobalPrincipals {
			principals = principalARNs(s.Account(edgeAccountOf(res)))
		}
		for _, p := range principals {
			r := spec.Eval(p, res)
			if !r.Allowed {
				continue
			}
			if spec.EdgeFn != nil {
				if e := spec.EdgeFn(p, res, r); e != nil {
					out = append(out, e)
				}
				continue
			}
			e := graph.NewEdge(p, res, spec.Kind)
			if !spec.OmitTraversable {
				e.Set("is_traversable", spec.Traversable)
			}
			e.Set("allow_sources", strings.Join(r.AllowSources, ", "))
			e.Set("conditions", conditionsJSON(r.Conditions))
			out = append(out, e)
		}
	}
	return out
}

// GenerateAccountScopedEdges emits the "action on resource "*" → account root"
// primitive for every principal in every account: a non-traversable capability
// edge whose conditions ride on condKey (default "conditions"; some families use
// "service_action_conditions" so the pass-role composites can read them). This is
// the shared form of ssmAccountScopedEdge / ec2AccountEdge / the account-scoped
// cloudformation primitives.
func GenerateAccountScopedEdges(s *store.Store, pe *eval.PolicyEvaluator, action string, kind graph.EdgeKind, condKey string) []*graph.Edge {
	return GenerateResourceToRootEdges(s, pe, action, func(string) string { return "*" }, kind, condKey)
}

// GenerateResourceToRootEdges is GenerateAccountScopedEdges generalized to a
// per-account resource pattern (resourceFn), for wildcard-to-root primitives like
// iam:CreateUser on arn:aws:iam::<acct>:user/* → account root. A principal allowed
// action on resourceFn(account) earns a non-traversable edge to the account root.
func GenerateResourceToRootEdges(s *store.Store, pe *eval.PolicyEvaluator, action string, resourceFn func(accountID string) string, kind graph.EdgeKind, condKey string) []*graph.Edge {
	if condKey == "" {
		condKey = "conditions"
	}
	var out []*graph.Edge
	for _, a := range s.Accounts() {
		root := "arn:aws:iam::" + a.ID + ":root"
		resource := resourceFn(a.ID)
		for _, p := range principalARNs(a) {
			r := pe.CanPerformAction(p, action, resource, nil)
			if !r.Allowed {
				continue
			}
			e := graph.NewEdge(p, root, kind)
			e.Set("is_traversable", false)
			e.Set("allow_sources", strings.Join(r.AllowSources, ", "))
			e.Set(condKey, conditionsJSON(r.Conditions))
			out = append(out, e)
		}
	}
	return out
}

// CompositeAction is one leg of a multi-action composite: the IAM action and the
// resource it authorizes against, derived from the candidate (the same candidate
// for same-resource composites; a derived resource — e.g. a synthetic access-entry
// ARN from a cluster — for cross-resource ones). Resource returns (resource, ok);
// ok=false skips the candidate.
type CompositeAction struct {
	Action   string
	Resource func(candidate string) (string, bool)
}

// GenerateCompositeEdges emits at most one edge per (principal, candidate) where
// the principal is allowed EVERY action on the candidate (short-circuit on first
// denial). Same-resource composites (all actions evaluate the candidate); the edge
// is built by edgeFn from the ordered per-action results, keeping each composite's
// bespoke property schema.
func GenerateCompositeEdges(s *store.Store, pe *eval.PolicyEvaluator, actions []string, candidates func(*store.Store) []string, globalPrincipals bool, edgeFn func(principal, resource string, results []*eval.PermissionCheckResult) *graph.Edge) []*graph.Edge {
	legs := make([]CompositeAction, len(actions))
	for i, a := range actions {
		legs[i] = CompositeAction{Action: a, Resource: func(c string) (string, bool) { return c, true }}
	}
	return GenerateDerivedCompositeEdges(s, pe, legs, candidates, globalPrincipals, edgeFn)
}

// GenerateDerivedCompositeEdges is GenerateCompositeEdges where each action may
// authorize against a resource DERIVED from the candidate (cross-resource
// composites like eks create-and-associate: CreateAccessEntry on the cluster,
// AssociateAccessPolicy on the cluster's synthetic access-entry). The edge still
// points at the candidate.
func GenerateDerivedCompositeEdges(s *store.Store, pe *eval.PolicyEvaluator, actions []CompositeAction, candidates func(*store.Store) []string, globalPrincipals bool, edgeFn func(principal, candidate string, results []*eval.PermissionCheckResult) *graph.Edge) []*graph.Edge {
	var global []string
	if globalPrincipals {
		global = allPrincipals(s)
	}
	var out []*graph.Edge
	for _, candidate := range candidates(s) {
		resources := make([]string, len(actions))
		skip := false
		for i, a := range actions {
			r, ok := a.Resource(candidate)
			if !ok {
				skip = true
				break
			}
			resources[i] = r
		}
		if skip {
			continue
		}
		principals := global
		if !globalPrincipals {
			principals = principalARNs(s.Account(edgeAccountOf(candidate)))
		}
		for _, p := range principals {
			results := make([]*eval.PermissionCheckResult, 0, len(actions))
			ok := true
			for i, a := range actions {
				r := pe.CanPerformAction(p, a.Action, resources[i], nil)
				if !r.Allowed {
					ok = false
					break
				}
				results = append(results, r)
			}
			if !ok {
				continue
			}
			if e := edgeFn(p, candidate, results); e != nil {
				out = append(out, e)
			}
		}
	}
	return out
}

// GenerateFirstAllowedEdges emits one edge per principal allowed action on ANY of
// a candidate's derived resources — first match wins, short-circuiting (the
// "evaluate against each attached volume, first allow wins" pattern of ec2
// CreateSnapshot/CreateImage). derivedFn maps the candidate to the resources to
// try; edgeFn builds the edge (typically pointing at the candidate) from the first
// allowing result.
func GenerateFirstAllowedEdges(s *store.Store, pe *eval.PolicyEvaluator, action string, candidates func(*store.Store) []string, derivedFn func(candidate string) []string, edgeFn func(principal, candidate string, res *eval.PermissionCheckResult) *graph.Edge) []*graph.Edge {
	var out []*graph.Edge
	for _, candidate := range candidates(s) {
		derived := derivedFn(candidate)
		if len(derived) == 0 {
			continue
		}
		for _, p := range principalARNs(s.Account(edgeAccountOf(candidate))) {
			for _, r := range derived {
				res := pe.CanPerformAction(p, action, r, nil)
				if res.Allowed {
					if e := edgeFn(p, candidate, res); e != nil {
						out = append(out, e)
					}
					break
				}
			}
		}
	}
	return out
}

// allPrincipals returns every account's principals (users + roles), sorted — the
// global candidate set for cross-account union families.
func allPrincipals(s *store.Store) []string {
	var out []string
	for _, a := range s.Accounts() {
		out = append(out, principalARNs(a)...)
	}
	sort.Strings(out)
	return out
}

// RoleTrustStrategy is the ResourceFactorFunc for the mandatory role-trust class:
// it produces the trust-admit factor for the role at resourceArn (a role whose ARN
// is not in the store admits nobody).
func RoleTrustStrategy(s *store.Store, pe *eval.PolicyEvaluator, resourceArn string, principals []string) eval.Factor {
	acct := s.Account(edgeAccountOf(resourceArn))
	role := acct.Roles[resourceArn]
	if role == nil {
		return eval.Factor{}
	}
	return pe.TrustFactor(role, principals)
}

// sortedARNsOfType returns every interned ARN of the given resource type, sorted.
func sortedARNsOfType(s *store.Store, t string) []string {
	ids := s.ARN().TypeBitmap(t).ToArray()
	arns := make([]string, 0, len(ids))
	for _, id := range ids {
		arns = append(arns, s.ARN().Arn(id))
	}
	sort.Strings(arns)
	return arns
}

// filterPrincipalsByBitmap returns the principals whose interned id is in allow,
// preserving order, into a fresh slice (the input is not mutated). Used by the
// mandatory-identity candidate pre-filter in GenerateEdges.
func filterPrincipalsByBitmap(s *store.Store, principals []string, allow *roaring.Bitmap) []string {
	out := make([]string, 0, len(principals))
	for _, p := range principals {
		if id, ok := s.ARN().ID(p); ok && allow.Contains(id) {
			out = append(out, p)
		}
	}
	return out
}

// principalIDMask returns the bitmap of interned ids for the given principal ARNs.
func principalIDMask(s *store.Store, principals []string) *roaring.Bitmap {
	m := roaring.New()
	for _, p := range principals {
		if id, ok := s.ARN().ID(p); ok {
			m.Add(id)
		}
	}
	return m
}

// edgeAccountOf returns the account-id segment (index 4) of an ARN, or "".
func edgeAccountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
