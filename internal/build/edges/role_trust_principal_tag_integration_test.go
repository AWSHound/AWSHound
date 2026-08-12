package edges_test

import (
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// A trust policy's aws:PrincipalTag condition is evaluated from the assuming
// role's persistent IAM tags. This fixture deliberately has no STS session tags
// or session policies: the otherwise-identical untagged role must not be able to
// cross the account boundary.
func TestRoleTrustEdgesEvaluatePersistentPrincipalTags(t *testing.T) {
	const (
		sourceAccount = "111122223333"
		targetAccount = "444455556666"
		taggedRole    = "arn:aws:iam::111122223333:role/student01-katia"
		untaggedRole  = "arn:aws:iam::111122223333:role/student02-katia"
		targetRole    = "arn:aws:iam::444455556666:role/student01-odette"
	)

	assumeTarget := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::444455556666:role/student01-odette"}]}`
	taggedTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalTag/Student":"student01"}}}]}`

	s := store.New()
	s.AddAuthDetails(sourceAccount, &model.AuthDetails{RoleDetailList: []model.RoleDetail{
		{
			Arn:      taggedRole,
			RoleName: "student01-katia",
			Tags:     []model.Tag{{Key: "Student", Value: "student01"}},
			RolePolicyList: []model.InlinePolicy{{
				PolicyName: "assume-odette", PolicyDocument: assumeTarget,
			}},
		},
		{
			Arn:      untaggedRole,
			RoleName: "student02-katia",
			RolePolicyList: []model.InlinePolicy{{
				PolicyName: "assume-odette", PolicyDocument: assumeTarget,
			}},
		},
	}})
	s.AddAuthDetails(targetAccount, &model.AuthDetails{RoleDetailList: []model.RoleDetail{{
		Arn:                      targetRole,
		RoleName:                 "student01-odette",
		AssumeRolePolicyDocument: taggedTrust,
	}}})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	var got []*graph.Edge
	for _, edge := range edges.RoleTrustEdges(s, pe) {
		if edge.Kind == graph.KindCanAssumeRole && edge.End == targetRole {
			got = append(got, edge)
		}
	}

	if len(got) != 1 {
		t.Fatalf("want exactly the persistently tagged role to assume the target, got %d edges: %+v", len(got), got)
	}
	if got[0].Start != taggedRole {
		t.Fatalf("assume edge starts at %q, want persistently tagged role %q", got[0].Start, taggedRole)
	}

	conditions, ok := got[0].Props.Get("trust_policy_conditions").(string)
	if !ok || !strings.Contains(conditions, "aws:PrincipalTag/Student") {
		t.Fatalf("assume edge does not retain its principal-tag trust condition: %q", conditions)
	}
}
