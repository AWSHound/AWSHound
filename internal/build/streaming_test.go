package build_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func nodeJSON(t *testing.T, n *graph.Node) string {
	t.Helper()
	b, err := n.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// referenceNodes is the accumulate-then-merge path StreamNodes must reproduce.
func referenceNodes(s *store.Store) []*graph.Node {
	var all []*graph.Node
	for _, acct := range s.Accounts() {
		all = append(all, build.AccountNodes(acct)...)
	}
	return build.MergeNodes(all)
}

// StreamNodes must emit exactly the sequence MergeNodes(concat AccountNodes)
// produces — same first-appearance order, same last-wins properties for
// cross-account-shared (AWS-managed) nodes — while account-local nodes stream
// through without accumulating (§9 of docs/authorization-tensor.md). This pins
// byte-identity, including last-wins on a shared AWS-managed policy whose
// attachment_count differs per account.
func TestStreamNodesMatchesMergeNodes(t *testing.T) {
	s := store.New()
	awsPol := func(count int) model.PolicyDetail {
		return model.PolicyDetail{
			Arn: "arn:aws:iam::aws:policy/AdministratorAccess", PolicyName: "AdministratorAccess",
			PolicyId: "ANPAI", AttachmentCount: count,
		}
	}
	s.AddAuthDetails("111111111111", &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: "arn:aws:iam::111111111111:user/a", UserName: "a"}},
		Policies:       []model.PolicyDetail{awsPol(5)},
	})
	s.AddAuthDetails("222222222222", &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: "arn:aws:iam::222222222222:user/b", UserName: "b"}},
		Policies:       []model.PolicyDetail{awsPol(9)}, // last account wins
	})

	var ref []string
	for _, n := range referenceNodes(s) {
		ref = append(ref, nodeJSON(t, n))
	}
	var got []string
	build.StreamNodes(s, func(n *graph.Node) { got = append(got, nodeJSON(t, n)) })

	if len(got) != len(ref) {
		t.Fatalf("StreamNodes emitted %d nodes, MergeNodes %d", len(got), len(ref))
	}
	for i := range ref {
		if got[i] != ref[i] {
			t.Fatalf("node %d differs:\n stream: %s\n merge:  %s", i, got[i], ref[i])
		}
	}
}
