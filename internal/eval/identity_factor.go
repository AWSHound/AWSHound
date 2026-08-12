package eval

import "github.com/RoaringBitmap/roaring/v2"

// IdentityFactor inverts the identity side for a fixed (action, resource): over
// the given candidate principals it produces a Factor whose planes are indexed by
// interned principal id. This is the §6 "invert identity into the resource's
// space" primitive — the seam between the per-principal policy arbiter
// (CanPerformAction) and the bitwise decision algebra (Factor/Decision).
//
// CanPerformAction already applies explicit-deny precedence and the SCP/boundary
// ceilings per principal, so a principal is classified as a definite allow (Allow
// plane) or, when the allow rode in on unresolved conditions, a conditional allow
// (CondAllow plane). Denies surface as absence, so the Deny/CondDeny planes stay
// empty here; the arbiter has already subtracted them.
func (pe *PolicyEvaluator) IdentityFactor(action, resourceArn string, principals []string) Factor {
	allow := roaring.New()
	condAllow := roaring.New()
	for _, p := range principals {
		id, ok := pe.arn.ID(p)
		if !ok {
			continue
		}
		res := pe.CanPerformAction(p, action, resourceArn, nil)
		if !res.Allowed {
			continue
		}
		if len(res.Conditions) > 0 {
			condAllow.Add(id)
		} else {
			allow.Add(id)
		}
	}
	return Factor{Allow: allow, CondAllow: condAllow, Deny: roaring.New(), CondDeny: roaring.New()}
}
