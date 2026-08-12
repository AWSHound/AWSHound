package eval_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

const testAcct = "111122223333"

func userWithInlinePolicy(arn, name, doc string) *model.AuthDetails {
	return &model.AuthDetails{
		UserDetailList: []model.UserDetail{{
			Arn:            arn,
			UserName:       name,
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}},
		}},
	}
}

// Core allow / implicit-deny / resource-scoping semantics.
func TestEvaluatorAllowAndResourceScope(t *testing.T) {
	alice := "arn:aws:iam::111122223333:user/alice"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}`

	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(alice, "alice", doc))
	s.ARN().Intern("arn:aws:s3:::mybucket/file.txt")
	s.ARN().Intern("arn:aws:s3:::other/file.txt")

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	if r := pe.CanPerformAction(alice, "s3:GetObject", "arn:aws:s3:::mybucket/file.txt", nil); !r.Allowed {
		t.Errorf("expected ALLOW s3:GetObject on mybucket/*, got %+v", r)
	}
	if r := pe.CanPerformAction(alice, "s3:DeleteObject", "arn:aws:s3:::mybucket/file.txt", nil); r.Allowed {
		t.Errorf("expected implicit deny for ungranted s3:DeleteObject, got allowed")
	}
	if r := pe.CanPerformAction(alice, "s3:GetObject", "arn:aws:s3:::other/file.txt", nil); r.Allowed {
		t.Errorf("expected deny for out-of-scope resource, got allowed")
	}
}

// Explicit Deny must beat Allow, and Action "s3:*" must expand via the catalog.
func TestEvaluatorExplicitDenyAndWildcard(t *testing.T) {
	bob := "arn:aws:iam::111122223333:user/bob"
	doc := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(bob, "bob", doc))
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	// s3:GetObject is covered by the s3:* allow and not denied.
	if r := pe.CanPerformAction(bob, "s3:GetObject", "arn:aws:s3:::b/x", nil); !r.Allowed {
		t.Errorf("expected ALLOW s3:GetObject via s3:* wildcard, got %+v", r)
	}
	// s3:DeleteObject is allowed by s3:* but explicitly denied — deny wins.
	r := pe.CanPerformAction(bob, "s3:DeleteObject", "arn:aws:s3:::b/x", nil)
	if r.Allowed {
		t.Errorf("expected explicit DENY for s3:DeleteObject, got allowed")
	}
	if r.Outcome != eval.OutcomeExplicitDeny {
		t.Errorf("expected outcome EXPLICIT_DENY, got %q (%+v)", r.Outcome, r)
	}
}
