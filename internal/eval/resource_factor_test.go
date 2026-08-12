package eval_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// TrustFactor is the resource-side factor for the mandatory-policy class: over the
// candidate principals it produces the bitmap a role's trust policy admits. It is
// the resource-side analogue of IdentityFactor (§5.4/§6).
func TestTrustFactorAdmitsTrustedPrincipal(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	bob := "arn:aws:iam::111122223333:user/bob"
	roleArn := "arn:aws:iam::111122223333:role/target"
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"}]}`

	s := store.New()
	role := model.RoleDetail{Arn: roleArn, RoleName: "target", AssumeRolePolicyDocument: trust}
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice"}, {Arn: bob, UserName: "bob"}},
		RoleDetailList: []model.RoleDetail{role},
	})
	aliceID, _ := s.ARN().ID(alice)
	bobID, _ := s.ARN().ID(bob)

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	d := pe.TrustFactor(&role, []string{alice, bob}).Resolve(eval.AttackerBias)
	if !d.Allowed.Contains(aliceID) {
		t.Fatalf("expected trust to admit alice (%d), got %v", aliceID, d.Allowed.ToArray())
	}
	if d.Allowed.Contains(bobID) {
		t.Fatalf("trust must not admit bob (%d), got %v", bobID, d.Allowed.ToArray())
	}
}

// Role assumption is the MandatoryPolicy class: an edge requires BOTH identity
// (sts:AssumeRole) AND trust. A principal trusted by the role but lacking the
// identity permission gets no edge — even same-account (no free pass).
func TestMandatoryComposeRoleAssumption(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice" // has sts:AssumeRole + trusted
	carol := "arn:aws:iam::111122223333:user/carol" // trusted but no identity perm
	roleArn := "arn:aws:iam::111122223333:role/target"
	aliceDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`
	// Trust the whole account root -> admits both alice and carol.
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`

	s := store.New()
	role := model.RoleDetail{Arn: roleArn, RoleName: "target", AssumeRolePolicyDocument: trust}
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: alice, UserName: "alice", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: aliceDoc}}},
			{Arn: carol, UserName: "carol"},
		},
		RoleDetailList: []model.RoleDetail{role},
	})
	aliceID, _ := s.ARN().ID(alice)
	carolID, _ := s.ARN().ID(carol)

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	principals := []string{alice, carol}
	sameAcct := bm(aliceID, carolID)

	identity := pe.IdentityFactor("sts:AssumeRole", roleArn, principals).Resolve(eval.AttackerBias)
	trustD := pe.TrustFactor(&role, principals).Resolve(eval.AttackerBias)
	d := eval.Compose(identity, trustD, eval.MandatoryPolicy, sameAcct)

	if !d.Allowed.Contains(aliceID) {
		t.Fatalf("alice (identity+trust) should be able to assume, got %v", d.Allowed.ToArray())
	}
	if d.Allowed.Contains(carolID) {
		t.Fatalf("carol (trust only, no sts:AssumeRole) must NOT assume — mandatory needs both")
	}
}
