package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// EC2 instance ARNs are no longer interned (§4 eviction), yet per-instance edges
// must still be emitted: EC2Edges enumerates instances from the resource bag and
// CanPerformAction regex-matches the un-interned instance ARN.
func TestEC2InstanceEdgesSurviveEviction(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	instARN := "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc123"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:TerminateInstances","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
	})
	store.IngestEC2(s, acct, &model.EC2Data{
		AccountId: acct,
		Instances: []model.EC2Instance{{InstanceId: "i-0abc123", Region: "us-east-1"}},
	})

	if _, interned := s.ARN().ID(instARN); interned {
		t.Fatalf("instance ARN must not be interned into the eval universe after §4 eviction")
	}

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range edges.EC2Edges(s, pe) {
		if e.Start == alice && e.End == instARN && e.Kind == graph.KindCanTerminateInstances {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alice -[AWS_CanTerminateInstances]-> %s despite eviction", instARN)
	}
}
