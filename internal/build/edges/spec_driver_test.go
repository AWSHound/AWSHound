package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// The edge-spec driver generates an identity-governed family from a declarative
// spec (§10 of docs/authorization-tensor.md): it type-filters candidate resources
// to the spec's target type and emits principal->resource edges where the identity
// side allows. A wrong-type resource (a role, for ssm:GetParameter) is never a
// candidate, proving the type filter.
func TestGenerateIdentityGovernedEdges(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	roleArn := "arn:aws:iam::111122223333:role/somerole"
	param := "arn:aws:ssm:us-east-1:111122223333:parameter/foo"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"arn:aws:ssm:*:*:parameter/*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
		RoleDetailList: []model.RoleDetail{{Arn: roleArn, RoleName: "somerole",
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[]}`}},
	})
	s.ARN().Intern(param)

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	spec := edges.IdentitySpec{
		Action: "ssm:GetParameter", Kind: graph.KindCanGetParameter, TargetType: "parameter",
	}
	got := edges.GenerateIdentityGovernedEdges(s, pe, spec)

	if len(got) != 1 {
		t.Fatalf("want exactly one edge (alice->param), got %d: %+v", len(got), got)
	}
	e := got[0]
	if e.Start != alice || e.End != param || e.Kind != graph.KindCanGetParameter {
		t.Fatalf("edge = %s -[%s]-> %s, want alice -[AWS_CanGetParameter]-> param", e.Start, e.Kind, e.End)
	}
}

// edgeKey serializes an edge (endpoints, kind, properties) for set comparison.
func edgeKey(t *testing.T, e *graph.Edge) string {
	t.Helper()
	b, err := e.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The spec driver must reproduce the existing hand-written family byte-for-byte
// (the §11 validation gate): for each identity-governed parameter action, its
// edges equal SSMEdges' edges of the corresponding kind on the same store.
func TestSpecDriverMatchesSSMFamily(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	// alice may get, put, and delete parameters — one edge of each kind.
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:PutParameter","ssm:DeleteParameter"],"Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
	})
	store.IngestSSM(s, acct, &model.SSMData{
		AccountId:  acct,
		Parameters: []model.SSMParameter{{Name: "/prod/db", Region: "us-east-1"}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	family := edges.SSMEdges(s, pe)

	specs := []edges.IdentitySpec{
		{Action: "ssm:GetParameter", Kind: graph.KindCanGetParameter, TargetType: "parameter"},
		{Action: "ssm:PutParameter", Kind: graph.KindCanPutParameter, TargetType: "parameter"},
		{Action: "ssm:DeleteParameter", Kind: graph.KindCanDeleteParameter, TargetType: "parameter"},
	}
	for _, spec := range specs {
		t.Run(string(spec.Kind), func(t *testing.T) {
			want := map[string]bool{}
			for _, e := range family {
				if e.Kind == spec.Kind {
					want[edgeKey(t, e)] = true
				}
			}
			if len(want) == 0 {
				t.Fatalf("reference family produced no %s edges to compare against", spec.Kind)
			}
			got := map[string]bool{}
			for _, e := range edges.GenerateIdentityGovernedEdges(s, pe, spec) {
				got[edgeKey(t, e)] = true
			}
			if len(got) != len(want) {
				t.Fatalf("driver produced %d %s edges, family %d", len(got), spec.Kind, len(want))
			}
			for k := range want {
				if !got[k] {
					t.Fatalf("driver missing %s edge produced by family:\n%s", spec.Kind, k)
				}
			}
		})
	}
}
