package eval_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/store"
)

// IdentityFactor inverts the identity side for a fixed (action, resource): it
// classifies each candidate principal into allow / condAllow planes over the
// principal-id space (§6 of docs/authorization-tensor.md). A definite grant lands
// in Allow, so Resolve yields it as non-conditional.
func TestIdentityFactorDefiniteAllow(t *testing.T) {
	alice := "arn:aws:iam::111122223333:user/alice"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(alice, "alice", doc))
	res := "arn:aws:s3:::mybucket/file.txt"
	s.ARN().Intern(res)
	aliceID, _ := s.ARN().ID(alice)

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	f := pe.IdentityFactor("s3:GetObject", res, []string{alice})
	d := f.Resolve(eval.AttackerBias)
	if !d.Allowed.Contains(aliceID) {
		t.Fatalf("expected alice (%d) allowed, got %v", aliceID, d.Allowed.ToArray())
	}
	if d.Conditional.Contains(aliceID) {
		t.Fatalf("definite grant must not be conditional")
	}
}

// A grant gated by an unresolvable request-context condition (e.g. MFA) is an
// allow under attacker bias but lands in the CondAllow plane, so Resolve marks it
// conditional.
func TestIdentityFactorConditionalAllow(t *testing.T) {
	bob := "arn:aws:iam::111122223333:user/bob"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(bob, "bob", doc))
	res := "arn:aws:s3:::mybucket/file.txt"
	s.ARN().Intern(res)
	bobID, _ := s.ARN().ID(bob)

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	d := pe.IdentityFactor("s3:GetObject", res, []string{bob}).Resolve(eval.AttackerBias)
	if !d.Allowed.Contains(bobID) {
		t.Fatalf("expected conditional allow for bob, got %v", d.Allowed.ToArray())
	}
	if !d.Conditional.Contains(bobID) {
		t.Fatalf("expected bob in conditional set, got %v", d.Conditional.ToArray())
	}
}
