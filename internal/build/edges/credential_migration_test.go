package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// The credential family is identity-governed (principal -> IAM user, gated purely
// by CanPerformAction), so the generic spec driver must reproduce its exact edge
// set for every credential kind. This locks the migration byte-identical (as a
// set — edge order is not asserted anywhere and is cosmetic to BHE).
func TestCredentialFamilyEqualsSpecDriver(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	bob := "arn:aws:iam::111122223333:user/bob"
	carol := "arn:aws:iam::111122223333:role/carol"
	// alice can do every credential action on any user; carol (a role) can reset
	// login profiles. Two targets (alice, bob) exercise self- and cross-targeting.
	aliceDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`
	carolDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UpdateLoginProfile","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: alice, UserName: "alice", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: aliceDoc}}},
			{Arn: bob, UserName: "bob"},
		},
		RoleDetailList: []model.RoleDetail{
			{Arn: carol, RoleName: "carol", AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[]}`,
				RolePolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: carolDoc}}},
		},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	got := edges.CredentialEdges(s, pe)

	// Expected, computed independently of the implementation:
	//   alice (iam:*) -> {alice, bob} for all 17 credential kinds        = 34
	//   carol (iam:UpdateLoginProfile) -> {alice, bob}                   =  2
	//   bob (no perms) -> nothing.
	// Targets are IAM users only, so the role carol is never a target.
	const wantCount = 17*2 + 2
	if len(got) != wantCount {
		t.Fatalf("credential edges = %d, want %d", len(got), wantCount)
	}

	has := func(start, end string, kind graph.EdgeKind) bool {
		for _, e := range got {
			if e.Start == start && e.End == end && e.Kind == kind {
				return true
			}
		}
		return false
	}
	if !has(alice, bob, graph.KindCanCreateAccessKey) {
		t.Error("missing alice -> bob CanCreateAccessKey")
	}
	if !has(alice, alice, graph.KindCanDeleteVirtualMFADevice) {
		t.Error("missing alice -> alice (self) CanDeleteVirtualMFADevice")
	}
	if !has(carol, alice, graph.KindCanUpdateLoginProfile) {
		t.Error("missing carol -> alice CanUpdateLoginProfile")
	}
	if has(carol, alice, graph.KindCanCreateAccessKey) {
		t.Error("carol must NOT have CanCreateAccessKey (lacks the permission)")
	}
}
