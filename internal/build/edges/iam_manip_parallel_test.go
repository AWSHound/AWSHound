package edges

import (
	"encoding/json"
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// escalationAccount adds an account whose IAM lets `alice` attach a policy to any
// user (a CanAttachUserPolicy / CanUpdateSelfPolicy escalation primitive) and
// assume any role, with a role that trusts alice — enough to drive the
// iam_manipulation family's principals×resources CanPerformAction + CheckTrustPolicy
// legs, so the parallel/sequential comparison covers real per-account work.
func escalationAccount(s *store.Store, acctID string) {
	alice := "arn:aws:iam::" + acctID + ":user/alice"
	role := "arn:aws:iam::" + acctID + ":role/app"
	inline := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:AttachUserPolicy","sts:AssumeRole"],"Resource":"*"}]}`
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + alice + `"},"Action":"sts:AssumeRole"}]}`
	s.AddAuthDetails(acctID, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: alice, UserName: "alice", UserPolicyList: []model.InlinePolicy{{PolicyName: "esc", PolicyDocument: inline}}},
			{Arn: "arn:aws:iam::" + acctID + ":user/bob", UserName: "bob"},
		},
		RoleDetailList: []model.RoleDetail{
			{Arn: role, RoleName: "app", AssumeRolePolicyDocument: trust},
		},
	})
}

// edgeKeys serializes an edge slice to its ordered JSON forms — Start/End/Kind plus
// the ordered Props — so two builds can be compared exactly (order and content).
func edgeKeys(t *testing.T, es []*graph.Edge) []string {
	t.Helper()
	out := make([]string, len(es))
	for i, e := range es {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal edge: %v", err)
		}
		out[i] = string(b)
	}
	return out
}

// buildManip builds the iam_manipulation family with a fixed worker count (0 =>
// runtime.NumCPU()), restoring the override afterward.
func buildManip(t *testing.T, s *store.Store, workers int) []string {
	t.Helper()
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	prev := iamManipMaxWorkers
	iamManipMaxWorkers = workers
	defer func() { iamManipMaxWorkers = prev }()
	return edgeKeys(t, IAMManipulationEdges(s, pe))
}

// TestIAMManipulationParallelMatchesSequential is the correctness guarantee for the
// per-account fan-out: the parallel build (NumCPU workers) must emit byte-identical
// edges — same order, same properties — as the forced-sequential build (1 worker),
// and must be deterministic across repeated parallel runs. A concurrency bug in the
// shared memo or evaluator would surface here as an order or content difference.
func TestIAMManipulationParallelMatchesSequential(t *testing.T) {
	s := store.New()
	// Several accounts, spanning the id-sort order, each with real per-account work.
	for _, id := range []string{"111111111111", "222222222222", "333333333333", "444444444444", "555555555555", "666666666666"} {
		escalationAccount(s, id)
	}

	seq := buildManip(t, s, 1)
	if len(seq) == 0 {
		t.Fatal("fixture produced no iam_manipulation edges; comparison is meaningless")
	}

	// Parallel must equal sequential, and be stable across runs.
	for run := 0; run < 5; run++ {
		par := buildManip(t, s, 0) // 0 => runtime.NumCPU()
		if len(par) != len(seq) {
			t.Fatalf("run %d: parallel produced %d edges, sequential %d", run, len(par), len(seq))
		}
		for i := range seq {
			if par[i] != seq[i] {
				t.Fatalf("run %d: edge %d differs:\n parallel: %s\n   seq:    %s", run, i, par[i], seq[i])
			}
		}
	}
	t.Logf("parallel == sequential across 5 runs (%d edges, %d accounts)", len(seq), len(s.Accounts()))
}
