package eval

import "github.com/RoaringBitmap/roaring/v2"

// Bias selects attacker- or defender-favorable resolution of conditional bits.
type Bias int

const (
	// AttackerBias keeps UNKNOWN allows (as conditional) and drops UNKNOWN denies.
	AttackerBias Bias = iota
	// DefenderBias drops UNKNOWN allows and keeps UNKNOWN denies (as blocking).
	DefenderBias
)

// Factor is a tri-state authorization result over one coordinate space (dense int
// ids — principals or resources), carried as four roaring bit-planes.
type Factor struct{ Allow, CondAllow, Deny, CondDeny *roaring.Bitmap }

// Decision is a resolved authorization result: the Allowed set and the subset of
// it that is conditional.
type Decision struct{ Allowed, Conditional *roaring.Bitmap }

// Resolve collapses the four planes to a Decision under bias b.
//
//	attacker: allowed = (allow ∨ condAllow) ANDNOT deny
//	defender: allowed =  allow            ANDNOT (deny ∨ condDeny)
//
// Bias is applied here so a single set of four raw planes serves both audiences
// with no recompute (§5.2 of docs/authorization-tensor.md).
func (f Factor) Resolve(b Bias) Decision {
	var allowed, denied *roaring.Bitmap
	switch b {
	case DefenderBias:
		allowed = nz(f.Allow).Clone()
		denied = or(f.Deny, f.CondDeny)
	default: // AttackerBias
		allowed = or(f.Allow, f.CondAllow)
		denied = nz(f.Deny).Clone()
	}
	allowed.AndNot(denied)
	// An allowed principal is conditional iff its only support was a conditional
	// allow — i.e., it survived but is not in the definite Allow plane.
	conditional := allowed.Clone()
	conditional.AndNot(nz(f.Allow))
	return Decision{Allowed: allowed, Conditional: conditional}
}

// ResourceClass selects how a resource's admit-decision composes with the
// identity decision (§5.4 of docs/authorization-tensor.md).
type ResourceClass int

const (
	// IdentityGoverned: no resource policy; access is identity ∧ same-account.
	IdentityGoverned ResourceClass = iota
	// MandatoryPolicy: resource policy always required (role trust); access is
	// identity ∧ resource, even same-account.
	MandatoryPolicy
	// OptionalUnion: same-account access is identity ∨ resource (a resource-policy
	// grant alone suffices), cross-account is identity ∧ resource (S3, KMS).
	OptionalUnion
)

// and returns a fresh bitmap = a ∩ b, treating nil as empty.
func and(a, b *roaring.Bitmap) *roaring.Bitmap {
	out := nz(a).Clone()
	out.And(nz(b))
	return out
}

// definite returns the definitely-allowed subset of a decision (Allowed minus
// Conditional).
func (d Decision) definite() *roaring.Bitmap {
	out := nz(d.Allowed).Clone()
	out.AndNot(nz(d.Conditional))
	return out
}

// withDefinite builds a Decision from an allowed set and its definitely-allowed
// subset: Conditional is whatever is allowed but not definite.
func withDefinite(allowed, definite *roaring.Bitmap) Decision {
	cond := allowed.Clone()
	cond.AndNot(definite)
	return Decision{Allowed: allowed, Conditional: cond}
}

// Compose combines an identity decision with a resource-admit decision under the
// resource's class. sameAcct is the mask of principals in the resource's account.
func Compose(identity, resource Decision, class ResourceClass, sameAcct *roaring.Bitmap) Decision {
	switch class {
	case IdentityGoverned:
		// Resource contributes only the (definite) same-account mask.
		allowed := nz(identity.Allowed).Clone()
		allowed.And(nz(sameAcct))
		def := identity.definite()
		def.And(nz(sameAcct))
		return withDefinite(allowed, def)
	case MandatoryPolicy:
		// Identity AND resource, always (same-account gets no free pass). Definite
		// only where both sides are definite.
		allowed := and(identity.Allowed, resource.Allowed)
		def := and(identity.definite(), resource.definite())
		return withDefinite(allowed, def)
	case OptionalUnion:
		same := nz(sameAcct) // read-only; the cross slice is its complement (AndNot)
		// same-account slice: identity ∨ resource; cross-account slice: identity ∧ resource.
		sameAllowed := and(or(identity.Allowed, resource.Allowed), same)
		crossAllowed := and(identity.Allowed, resource.Allowed)
		crossAllowed.AndNot(same)
		allowed := or(sameAllowed, crossAllowed)
		// Definite: same-account needs a definite on EITHER side; cross needs BOTH.
		sameDef := and(or(identity.definite(), resource.definite()), same)
		crossDef := and(identity.definite(), resource.definite())
		crossDef.AndNot(same)
		return withDefinite(allowed, or(sameDef, crossDef))
	default:
		panic("eval: unknown resource class")
	}
}

// Ceiling intersects the decision with an allow-set (an SCP, permission boundary,
// or RCP allow bitmap): principals outside allow are removed, and Conditional is
// trimmed to stay a subset of Allowed.
func (d Decision) Ceiling(allow *roaring.Bitmap) Decision {
	a := nz(d.Allowed).Clone()
	a.And(nz(allow))
	c := nz(d.Conditional).Clone()
	c.And(a)
	return Decision{Allowed: a, Conditional: c}
}

// nz returns b, or a fresh empty bitmap when b is nil.
func nz(b *roaring.Bitmap) *roaring.Bitmap {
	if b == nil {
		return roaring.New()
	}
	return b
}

// or returns a fresh bitmap = a ∪ b, treating nil as empty.
func or(a, b *roaring.Bitmap) *roaring.Bitmap {
	out := nz(a).Clone()
	out.Or(nz(b))
	return out
}
