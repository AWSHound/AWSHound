package edges_test

import (
	"sync/atomic"
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// TestEdgesProducedOffline drives the full edge pipeline with no AWS: a small
// synthetic org (group membership, an attached managed policy, and an identity
// policy granting iam:AttachUserPolicy) must produce the corresponding
// structural edges AND the evaluator-gated attack-path edge.
func TestEdgesProducedOffline(t *testing.T) {
	const acct = "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	bob := "arn:aws:iam::111122223333:user/bob"
	admins := "arn:aws:iam::111122223333:group/admins"
	powerUser := "arn:aws:iam::111122223333:policy/PowerUser"

	// alice can attach a managed policy to any user — an escalation primitive.
	aliceInline := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{
				Arn: alice, UserName: "alice", GroupList: []string{"admins"},
				UserPolicyList: []model.InlinePolicy{{PolicyName: "esc", PolicyDocument: aliceInline}},
			},
			{Arn: bob, UserName: "bob"},
		},
		GroupDetailList: []model.GroupDetail{{
			Arn: admins, GroupName: "admins",
			AttachedManagedPols: []model.AttachedPolicy{{PolicyName: "PowerUser", PolicyArn: powerUser}},
		}},
		Policies: []model.PolicyDetail{{Arn: powerUser, PolicyName: "PowerUser"}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	all := edges.AllEdges(s, pe)
	if len(all) == 0 {
		t.Fatal("no edges produced")
	}
	kinds := map[graph.EdgeKind]int{}
	for _, e := range all {
		kinds[e.Kind]++
	}

	// Structural (membership + attached policy) and the evaluator-gated attack edge.
	for _, want := range []graph.EdgeKind{
		graph.KindMemberOf,
		graph.KindHasMember,
		graph.KindHasPolicy,
		graph.KindCanAttachUserPolicy,
	} {
		if kinds[want] == 0 {
			t.Errorf("expected edge kind %s; got %v", want, kinds)
		}
	}
	t.Logf("produced %d edges across %d kinds: %v", len(all), len(kinds), kinds)
}

// TestEdgeProgressAccounting verifies the finer-grained Build edges progress: the
// denominator grows by iam_manipulation's per-account units plus S3's
// per-principal units, and matching ticks still land at 100%.
func TestEdgeProgressAccounting(t *testing.T) {
	s := store.New()
	// Two accounts, so iam_manipulation's per-account unit count is unambiguously
	// 2 (not coincidentally equal to some other family's output).
	for _, acct := range []string{"111122223333", "444455556666"} {
		s.AddAuthDetails(acct, &model.AuthDetails{
			UserDetailList: []model.UserDetail{
				{Arn: "arn:aws:iam::" + acct + ":user/u", UserName: "u"},
			},
		})
	}
	nAccts := len(s.Accounts())
	nPrincipals := nAccts // the fixture has one user in each account

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	// iam_manipulation builds accounts on a worker pool, so Advance (the per-item
	// onItem tick) fires from multiple goroutines — count atomically. AddTotal is
	// still called single-threaded before the fan-out, but keep it atomic too.
	var added, ticks atomic.Int64
	edges.AllEdgesProgress(s, pe, edges.EdgeProgress{
		AddTotal: func(n int) { added.Add(int64(n)) },
		Advance:  func() { ticks.Add(1) },
	})

	wantAdded := nAccts + nPrincipals
	if int(added.Load()) != wantAdded {
		t.Errorf("AddTotal grew denominator by %d; want %d (IAM accounts + S3 principals)", added.Load(), wantAdded)
	}
	wantTicks := int64(edges.NumFamilies() + wantAdded)
	if ticks.Load() != wantTicks {
		t.Errorf("got %d Advance ticks; want %d", ticks.Load(), wantTicks)
	}
	// The stage seeds tot=NumFamilies() and grows it by `added`; cur is `ticks`.
	// Completion requires cur == tot.
	if gotTot := int64(edges.NumFamilies()) + added.Load(); ticks.Load() != gotTot {
		t.Errorf("progress would not reach 100%%: cur=%d tot=%d", ticks.Load(), gotTot)
	}
}
