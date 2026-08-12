package eval

import (
	"github.com/RoaringBitmap/roaring/v2"
	"github.com/AWSHound/AWSHound/internal/model"
)

// TrustFactor is the resource-side factor for the mandatory-policy class (role
// trust): over the candidate principals it produces the Factor a role's trust
// policy admits for sts:AssumeRole, keyed by interned principal id. It is the
// resource-side analogue of IdentityFactor — the two compose under
// Compose(..., MandatoryPolicy, ...) to yield the assume-role edge set (§5.4/§6).
//
// A trust admittance gated by unresolved conditions lands in the CondAllow plane;
// CheckTrustPolicy already resolves the trust policy's own deny/allow arbitration,
// so the Deny/CondDeny planes stay empty.
func (pe *PolicyEvaluator) TrustFactor(role *model.RoleDetail, principals []string) Factor {
	allow := roaring.New()
	condAllow := roaring.New()
	for _, p := range principals {
		id, ok := pe.arn.ID(p)
		if !ok {
			continue
		}
		tr := pe.CheckTrustPolicy(role, p, nil)
		if tr == nil || !tr.Trusted {
			continue
		}
		if len(tr.Conditions) > 0 {
			condAllow.Add(id)
		} else {
			allow.Add(id)
		}
	}
	return Factor{Allow: allow, CondAllow: condAllow, Deny: roaring.New(), CondDeny: roaring.New()}
}
