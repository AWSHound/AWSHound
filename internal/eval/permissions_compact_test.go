package eval

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func TestCompressedPermissionsKeepAdminAndNotActionSymbolic(t *testing.T) {
	const (
		acct = "111122223333"
		arn  = "arn:aws:iam::111122223333:user/admin"
	)
	doc := `{"Version":"2012-10-17","Statement":[
		{"Sid":"admin","Effect":"Allow","Action":"*","Resource":"*"},
		{"Sid":"deny-delete","Effect":"Deny","NotAction":"s3:GetObject","Resource":"*"}
	]}`
	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{UserDetailList: []model.UserDetail{{
		Arn: arn, UserName: "admin", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}},
	}}})
	pe, err := NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	perms, err := pe.getPermissions(arn)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(perms.allowByAction.statements); got != 1 {
		t.Fatalf("admin allow compressed to %d logical statements, want 1", got)
	}
	if got := len(perms.denyByAction.statements); got != 1 {
		t.Fatalf("NotAction deny compressed to %d logical statements, want 1", got)
	}
	if got := len(perms.allowByAction.byAction); got != 0 {
		t.Fatalf("compression eagerly built %d action views, want none", got)
	}

	if !pe.CanPerformAction(arn, "s3:GetObject", "arn:aws:s3:::b/o", nil).Allowed {
		t.Fatal("admin allow did not survive symbolic action compression")
	}
	if pe.CanPerformAction(arn, "s3:DeleteObject", "arn:aws:s3:::b/o", nil).Allowed {
		t.Fatal("NotAction exclusion did not apply at lazy action selection")
	}
	if got := len(perms.allowByAction.byAction); got != 2 {
		t.Fatalf("queried action views = %d, want exactly the two queried actions", got)
	}
}

func TestComplementDenyKeepsFiniteIdentityScopeSymbolic(t *testing.T) {
	const (
		acct = "111122223333"
		arn  = "arn:aws:iam::111122223333:user/s3-admin"
	)
	doc := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::one/*","arn:aws:s3:::two/*"]},
		{"Effect":"Deny","NotAction":"s3:GetObject","Resource":"*"}
	]}`
	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{UserDetailList: []model.UserDetail{{
		Arn: arn, UserName: "s3-admin", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}},
	}}})
	pe, _ := NewPolicyEvaluator(s)
	perms, _ := pe.getPermissions(arn)
	deny := perms.denyByAction.statements[0]
	if !deny.identityScoped || !deny.complement {
		t.Fatal("finite complement deny was expanded instead of scoped symbolically")
	}
	if got := len(perms.identityActionScope); got != 1 {
		t.Fatalf("resource copies retained %d identity action scopes, want 1", got)
	}
	if got := pe.CanPerformAction(arn, "s3:DeleteObject", "*", nil).Outcome; got != OutcomeExplicitDeny {
		t.Fatalf("in-scope deny outcome = %s, want explicit", got)
	}
	if got := pe.CanPerformAction(arn, "ec2:StopInstances", "*", nil).Outcome; got != OutcomeImplicitDeny {
		t.Fatalf("out-of-scope deny outcome = %s, want implicit", got)
	}

	denyOnly := "arn:aws:iam::111122223333:user/deny-only"
	s2 := store.New()
	s2.AddAuthDetails(acct, &model.AuthDetails{UserDetailList: []model.UserDetail{{
		Arn: denyOnly, UserName: "deny-only", UserPolicyList: []model.InlinePolicy{{
			PolicyName: "p", PolicyDocument: `{"Statement":{"Effect":"Deny","NotAction":"s3:GetObject","Resource":"*"}}`,
		}},
	}}})
	pe2, _ := NewPolicyEvaluator(s2)
	if got := pe2.CanPerformAction(denyOnly, "s3:DeleteObject", "*", nil).Outcome; got != OutcomeImplicitDeny {
		t.Fatalf("deny-only complement outcome = %s, want implicit under the finite identity-universe bound", got)
	}
}
