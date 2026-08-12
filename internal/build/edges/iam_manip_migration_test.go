package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// iam_manipulation's group-targeted base edges (not consumed by the escalation
// composites) are generated through the shared identity driver. A principal with
// iam:DeleteGroup must earn the principal->group edge.
func TestIAMManipGroupEdgeViaDriver(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	admins := "arn:aws:iam::111122223333:group/admins"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteGroup","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
		GroupDetailList: []model.GroupDetail{{Arn: admins, GroupName: "admins"}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range edges.IAMManipulationEdges(s, pe) {
		if e.Start == alice && e.End == admins && e.Kind == graph.KindCanDeleteGroup {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alice -[AWS_CanDeleteGroup]-> %s via the identity driver", admins)
	}
}
