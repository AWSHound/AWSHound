package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// The generalized driver runs the mandatory (role-trust) class through the same
// harness: identity (sts:AssumeRole) AND resource (trust) both required. A
// principal trusted but lacking the identity permission gets no edge.
func TestGenerateEdgesMandatoryRoleTrust(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice" // identity + trusted -> edge
	carol := "arn:aws:iam::111122223333:user/carol" // trusted only -> no edge
	roleArn := "arn:aws:iam::111122223333:role/target"
	aliceDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: alice, UserName: "alice", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: aliceDoc}}},
			{Arn: carol, UserName: "carol"},
		},
		RoleDetailList: []model.RoleDetail{{Arn: roleArn, RoleName: "target", AssumeRolePolicyDocument: trust}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	got := edges.GenerateEdges(s, pe, edges.EdgeSpec{
		Action: "sts:AssumeRole", Kind: graph.KindCanAssumeRole, TargetType: "role",
		Traversable: true, Class: eval.MandatoryPolicy, Resource: edges.RoleTrustStrategy,
	})

	if len(got) != 1 {
		t.Fatalf("want exactly one assume edge (alice->role), got %d: %+v", len(got), got)
	}
	e := got[0]
	if e.Start != alice || e.End != roleArn || e.Kind != graph.KindCanAssumeRole {
		t.Fatalf("edge = %s -[%s]-> %s, want alice -[AWS_CanAssumeRole]-> role", e.Start, e.Kind, e.End)
	}
}
