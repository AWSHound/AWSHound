package eval

import (
	"slices"
	"strconv"
)

// IamPolicyEngine compiles IAM policy documents into bundled grants and combines
// a principal's identity policies, permissions boundary, SCPs, and RCPs into
// queryable effective permissions. Ported from
// awshound/core/evaluation/iam_policy/engine.py IamPolicyEngine.
//
// It is independent of the rest of AWSHound and depends only on the action
// catalog. The catalog is read-only after construction, so an IamPolicyEngine is
// safe for concurrent use.
type IamPolicyEngine struct {
	catalog *ActionCatalog
}

// NewIamPolicyEngine returns an engine over the given action catalog. Mirrors
// IamPolicyEngine.__init__.
func NewIamPolicyEngine(catalog *ActionCatalog) *IamPolicyEngine {
	return &IamPolicyEngine{catalog: catalog}
}

// Compile compiles one policy document into bundled grants. Ported from
// IamPolicyEngine.compile.
//
// source is the provenance prefix for each grant's Source (each grant's source
// becomes "<source>/<Sid-or-index>"). Action:"*" and NotAction:[...] compile to
// symbolic complement grants (Complement=true, Actions = the excluded set) rather
// than materializing the ~20k-action catalog. Combine preserves that form
// through the compact permission cache and lazy per-action lookup.
// Concrete actions and service wildcards ("s3:*") expand as usual.
//
// A nil document (a principal or resource with no policy) compiles to zero
// grants.
func (e *IamPolicyEngine) Compile(doc *Policy, source string) *CompiledPolicy {
	if doc == nil {
		return &CompiledPolicy{}
	}
	var grants []Grant
	for index := range doc.Statements {
		st := &doc.Statements[index]
		effect := EffectDeny
		if st.Effect == "Allow" {
			effect = EffectAllow
		}
		actions, complement := e.statementActions(st)
		sid := st.Sid
		if sid == "" {
			sid = strconv.Itoa(index)
		}
		stmtSource := source + "/" + sid
		condition := st.Condition
		for _, rp := range statementResources(st) {
			grants = append(grants, Grant{
				Actions:     actions,
				Resource:    rp.resource,
				NotResource: rp.notResource,
				Condition:   condition,
				Source:      stmtSource,
				Effect:      effect,
				Complement:  complement,
			})
		}
	}
	return &CompiledPolicy{Grants: grants}
}

// statementActions returns the (actions, complement) a statement names. Ported
// from IamPolicyEngine._statement_actions.
//
//   - Action with a bare "*"            -> (empty, true)   (all actions)
//   - NotAction: [E]                    -> (expand(E), true) (all actions except E)
//   - Action: [...] concrete/wildcard   -> (expanded, false)
//   - neither key present               -> (empty, false)
//
// A field is "present" when its normalized slice is non-nil (policy.go maps an
// absent key to nil and a present-but-empty key to a non-nil empty slice), so
// Action: [] is a present, empty, non-complement action set — a grant that names
// no action — while an absent Action falls through to NotAction.
func (e *IamPolicyEngine) statementActions(st *Statement) (ActionSet, bool) {
	if st.Action != nil {
		for _, entry := range st.Action {
			if entry == "*" {
				return NewActionSet(), true
			}
		}
		actions := NewActionSet()
		for _, entry := range st.Action {
			actions.addAll(e.catalog.ExpandPattern(entry))
		}
		return actions, false
	}
	if st.NotAction != nil {
		excluded := NewActionSet()
		for _, entry := range st.NotAction {
			excluded.addAll(e.catalog.ExpandPattern(entry))
		}
		return excluded, true
	}
	return NewActionSet(), false
}

// resourcePair is one (Resource, NotResource) constraint a statement applies to;
// exactly one side is non-nil for a freshly compiled grant, and both are nil for
// an unconstrained statement.
type resourcePair struct {
	resource    *string
	notResource *string
}

// statementResources returns the (resource, not_resource) pairs a statement
// applies to. Ported from IamPolicyEngine._statement_resources.
//
// A present-but-empty Resource (or NotResource) yields zero pairs — hence zero
// grants for that statement — matching the Python list comprehension over an
// empty list.
func statementResources(st *Statement) []resourcePair {
	if st.Resource != nil {
		pairs := make([]resourcePair, 0, len(st.Resource))
		for _, r := range st.Resource {
			res := r
			pairs = append(pairs, resourcePair{resource: &res})
		}
		return pairs
	}
	if st.NotResource != nil {
		pairs := make([]resourcePair, 0, len(st.NotResource))
		for _, nr := range st.NotResource {
			notRes := nr
			pairs = append(pairs, resourcePair{notResource: &notRes})
		}
		return pairs
	}
	return []resourcePair{{}}
}

// Combine combines a principal's compiled policies into effective permissions.
// Ported from IamPolicyEngine.combine.
//
// identity is the principal's own policies compiled to a single CompiledPolicy
// (managed + inline + group grants concatenated); its allows and denies are
// indexed as-is (the query layer resolves allow-vs-deny per resource). boundary
// is the permissions boundary or nil — a ceiling: an allow survives only where
// the boundary also allows it, and the boundary's own denies are added to the
// deny index.
//
// scpLevels and rcpLevels are the ordered SCP/RCP attach levels (root, each OU on
// the account's path, the account). AWS requires an action to be allowed at
// *every* level — intersection across levels, union within a level — so each
// level is applied as a sequential ceiling, which is exactly the across-level
// intersection. RCPs are composed after SCPs so the strictest applicable
// guardrail wins. A nil/empty level stack imposes no guardrail.
func (e *IamPolicyEngine) Combine(identity, boundary *CompiledPolicy, scpLevels, rcpLevels [][]*CompiledPolicy) *EffectivePermissions {
	var identityAllows, denies []Grant
	if identity != nil {
		for _, g := range identity.Grants {
			if g.Effect == EffectAllow {
				identityAllows = append(identityAllows, g)
			} else if g.Effect == EffectDeny {
				denies = append(denies, g)
			}
		}
	}
	allows := slices.Clone(identityAllows)

	if boundary != nil {
		allows = e.applyCeiling(allows, grantsOf(EffectAllow, boundary))
		denies = append(denies, grantsOf(EffectDeny, boundary)...)
	}
	allows, denies = e.applyLevels(allows, denies, scpLevels)
	allows, denies = e.applyLevels(allows, denies, rcpLevels)

	// Keep complement grants symbolic in the indexes. Expanding an admin
	// Action:"*" (or a NotAction allow/deny) across the full catalog multiplied
	// one logical statement into ~20k cached records per unique principal policy
	// set. Query-time selection applies its small exclusion set instead.
	perms := NewEffectivePermissions()
	// Preserve the prior identity-universe bound for complement denies: a deny on
	// an action the identity never grants is classified as implicit rather than
	// explicit. When an identity complement exists the universe is all and the
	// deny can stay symbolic; otherwise a query-time check against compact,
	// de-duplicated identity action selectors preserves that bound without
	// constructing its set difference.
	universeIsAll := false
	for _, grant := range identityAllows {
		if grant.Complement {
			universeIsAll = true
		}
	}
	for _, grant := range allows {
		indexGrant(&perms.AllowByAction, grant)
	}
	for _, grant := range denies {
		if grant.Complement && !universeIsAll {
			indexGrantScoped(&perms.DenyByAction, grant, true)
			continue
		}
		indexGrant(&perms.DenyByAction, grant)
	}
	if !universeIsAll {
		var previousSource string
		var previousActions ActionSet
		for _, grant := range identityAllows {
			if len(grant.Actions) == 0 {
				continue
			}
			// Compile emits one Grant per Resource but reuses the statement's
			// ActionSet. Collapse those adjacent copies before retaining the finite
			// identity-universe selector list.
			if grant.Source == previousSource && sameActionSet(grant.Actions, previousActions) {
				continue
			}
			perms.IdentityActionScope = append(perms.IdentityActionScope, grant.Actions)
			previousSource, previousActions = grant.Source, grant.Actions
		}
	}
	// Deny-cause indexes (consulted only when a query is denied): identity's
	// pre-ceiling allows, and each guardrail's own permitted set.
	for _, grant := range identityAllows {
		indexGrant(&perms.IdentityAllowByAction, grant)
	}
	if boundary != nil {
		for _, grant := range grantsOf(EffectAllow, boundary) {
			indexGrant(&perms.BoundaryAllowByAction, grant)
		}
	}
	// A guardrail that permits every action (complement of ∅ at every level, i.e.
	// only FullAWSAccess) is recorded as a flag, not a U-sized index. Concrete /
	// NotAction-restricted guardrails index normally (U-bounded).
	scpPermitted := e.guardrailPermitted(scpLevels)
	perms.ScpAllowPermitsAll = anyPermitsAll(scpPermitted)
	if !perms.ScpAllowPermitsAll {
		for _, grant := range scpPermitted {
			indexGrant(&perms.ScpAllowByAction, grant)
		}
	}
	rcpPermitted := e.guardrailPermitted(rcpLevels)
	perms.RcpAllowPermitsAll = anyPermitsAll(rcpPermitted)
	if !perms.RcpAllowPermitsAll {
		for _, grant := range rcpPermitted {
			indexGrant(&perms.RcpAllowByAction, grant)
		}
	}
	perms.HasBoundary = boundary != nil
	perms.HasSCP = len(scpLevels) > 0
	perms.HasRCP = len(rcpLevels) > 0
	return perms
}

func sameActionSet(a, b ActionSet) bool {
	if len(a) != len(b) {
		return false
	}
	for action := range a {
		if _, ok := b[action]; !ok {
			return false
		}
	}
	return true
}
