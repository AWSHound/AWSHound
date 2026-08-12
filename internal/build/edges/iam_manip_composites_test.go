package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func hasEdge(es []*graph.Edge, start, end string, kind graph.EdgeKind) bool {
	for _, e := range es {
		if e.Start == start && e.End == end && e.Kind == kind {
			return true
		}
	}
	return false
}

// Characterization test guarding the iam-manipulation escalation composites
// (CanUpdateSelfPolicy / CanUpdateOtherPolicy) before decoupling their base-edge
// inputs from the st.checks memo. These composites currently read the recorded
// base checks; this test pins their observable output so a refactor that lets the
// base edges migrate to the driver stays byte-identical. The family had no
// composite coverage.
func TestIAMManipEscalationComposites(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	bob := "arn:aws:iam::111122223333:user/bob"
	root := "arn:aws:iam::111122223333:root"

	// alice can put an inline policy on ANY user (incl. itself and bob): so it can
	// escalate its own privileges (CanUpdateSelfPolicy) and bob's (CanUpdateOtherPolicy).
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: alice, UserName: "alice", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}},
			{Arn: bob, UserName: "bob"},
		},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	es := edges.IAMManipulationEdges(s, pe)

	// alice can PutUserPolicy on itself -> self-escalation.
	if !hasEdge(es, alice, root, graph.KindCanUpdateSelfPolicy) {
		t.Error("expected alice CanUpdateSelfPolicy (can PutUserPolicy on itself)")
	}
	// CanUpdateOtherPolicy requires BOTH control (assume/mint-creds) AND
	// re-permission of the dest; alice can re-permission bob but cannot control it,
	// so it must NOT fire — pinning that gating.
	if hasEdge(es, alice, root, graph.KindCanUpdateOtherPolicy) {
		t.Error("alice must NOT have CanUpdateOtherPolicy (no control path to bob)")
	}
	// bob has no permissions -> no escalation.
	if hasEdge(es, bob, root, graph.KindCanUpdateSelfPolicy) {
		t.Error("bob must not have CanUpdateSelfPolicy")
	}
}
