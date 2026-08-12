package eval_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/RoaringBitmap/roaring/v2"
)

// bm builds a roaring bitmap from a list of ids.
func bm(ids ...uint32) *roaring.Bitmap {
	b := roaring.New()
	b.AddMany(ids)
	return b
}

// assertBits fails unless bitmap b holds exactly want (order-independent).
func assertBits(t *testing.T, b *roaring.Bitmap, want ...uint32) {
	t.Helper()
	got := b.ToArray()
	if len(got) != len(want) {
		t.Fatalf("bitmap = %v, want %v", got, want)
	}
	for _, w := range want {
		if !b.Contains(w) {
			t.Fatalf("bitmap = %v, missing %d (want %v)", got, w, want)
		}
	}
}

// Attacker bias: allowed = (allow ∨ condAllow) ANDNOT deny; condDeny is ignored.
func TestFactorResolveAttacker(t *testing.T) {
	f := eval.Factor{
		Allow:     bm(1, 2, 3),
		CondAllow: bm(4),
		Deny:      bm(3),
		CondDeny:  bm(2), // dropped under attacker bias -> 2 stays allowed
	}
	d := f.Resolve(eval.AttackerBias)
	assertBits(t, d.Allowed, 1, 2, 4)
}

// Deny SUBTRACTS from allow (ANDNOT), it does not AND with it: a principal that is
// both allowed and denied is absent from the result, not present.
func TestFactorDenySubtracts(t *testing.T) {
	f := eval.Factor{Allow: bm(1, 2), Deny: bm(2)}
	d := f.Resolve(eval.AttackerBias)
	assertBits(t, d.Allowed, 1)
}

// A principal allowed ONLY via condAllow is conditional; one with a definite allow
// is not. Conditional is always a subset of Allowed.
func TestFactorConditionalTracking(t *testing.T) {
	f := eval.Factor{
		Allow:     bm(1),    // definite
		CondAllow: bm(1, 2), // 1 also definite (wins), 2 conditional only
	}
	d := f.Resolve(eval.AttackerBias)
	assertBits(t, d.Allowed, 1, 2)
	assertBits(t, d.Conditional, 2)
}

// A conditional allow removed by a definite deny is neither allowed nor conditional.
func TestFactorConditionalDeniedIsGone(t *testing.T) {
	f := eval.Factor{CondAllow: bm(5), Deny: bm(5)}
	d := f.Resolve(eval.AttackerBias)
	assertBits(t, d.Allowed)
	assertBits(t, d.Conditional)
}

// Defender bias: allowed = allow ANDNOT (deny ∨ condDeny). Conditional allows are
// dropped, conditional denies now block.
func TestFactorResolveDefender(t *testing.T) {
	f := eval.Factor{
		Allow:     bm(1, 2, 3),
		CondAllow: bm(4), // dropped under defender bias
		Deny:      bm(3),
		CondDeny:  bm(2), // now blocks under defender bias
	}
	d := f.Resolve(eval.DefenderBias)
	assertBits(t, d.Allowed, 1)
	assertBits(t, d.Conditional) // no conditional allows in defender mode
}

// Ceiling intersects a decision with an allow-set (SCP / boundary / RCP), and the
// conditional subset is trimmed to stay ⊆ Allowed.
func TestDecisionCeiling(t *testing.T) {
	d := eval.Decision{Allowed: bm(1, 2, 3), Conditional: bm(2, 3)}
	capped := d.Ceiling(bm(1, 2)) // 3 is outside the ceiling
	assertBits(t, capped.Allowed, 1, 2)
	assertBits(t, capped.Conditional, 2)
}

// Identity-governed resources (no resource policy) admit only same-account
// principals per identity: Allowed = identity ∧ sameAcct; the resource side is
// ignored, and conditional identity grants stay conditional.
func TestComposeIdentityGoverned(t *testing.T) {
	identity := eval.Decision{Allowed: bm(1, 2, 3), Conditional: bm(2)}
	resource := eval.Decision{} // consulted for nothing in this class
	sameAcct := bm(1, 2)        // 3 is cross-account -> dropped
	d := eval.Compose(identity, resource, eval.IdentityGoverned, sameAcct)
	assertBits(t, d.Allowed, 1, 2)
	assertBits(t, d.Conditional, 2)
}

// Mandatory-policy resources (role trust) require BOTH identity and resource,
// even same-account (no same-account free pass). The edge is conditional if
// either side is conditional.
func TestComposeMandatory(t *testing.T) {
	identity := eval.Decision{Allowed: bm(1, 5, 6), Conditional: bm(6)}
	resource := eval.Decision{Allowed: bm(5, 6, 7)} // all definite
	// sameAcct must NOT grant a free pass here; pass a mask that would wrongly
	// admit 1 if the class ignored the resource side.
	d := eval.Compose(identity, resource, eval.MandatoryPolicy, bm(1, 5, 6))
	assertBits(t, d.Allowed, 5, 6) // 1 dropped: not admitted by resource
	assertBits(t, d.Conditional, 6)
}

// Optional-union resources (S3/KMS): same-account = identity ∨ resource (a
// resource-policy-only grant survives), cross-account = identity ∧ resource.
func TestComposeOptionalUnion(t *testing.T) {
	// sameAcct = {1,2,3}; 4,5,6 are cross-account.
	identity := eval.Decision{Allowed: bm(1, 3, 4, 5)}
	resource := eval.Decision{Allowed: bm(2, 3, 5, 6)}
	d := eval.Compose(identity, resource, eval.OptionalUnion, bm(1, 2, 3))
	// same-acct union: {1,2,3}; cross-acct AND: only 5. 4 (cross, id-only) and
	// 6 (cross, resource-only) are dropped. 2 (same-acct, resource-only) survives.
	assertBits(t, d.Allowed, 1, 2, 3, 5)
	assertBits(t, d.Conditional)
}
