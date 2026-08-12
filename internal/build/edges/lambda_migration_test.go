package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// Lambda's six account-scoped, function-scoped constituents are generated through
// the shared spec driver (§10). A single such grant (no meta consolidation
// triggered) must still surface the function-scoped edge — proving the migrated
// constituent path flows through LambdaEdges' meta pipeline. Lambda had no test.
func TestLambdaSimpleConstituentViaDriver(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	fnArn := "arn:aws:lambda:us-east-1:111122223333:function:worker"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
	})
	store.IngestLambda(s, acct, &model.LambdaData{
		AccountId: acct,
		Functions: []model.LambdaFunction{{FunctionName: "worker", FunctionArn: fnArn}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range edges.LambdaEdges(s, pe) {
		if e.Start == alice && e.End == fnArn && e.Kind == graph.KindCanUpdateLambdaCode {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alice -[AWS_CanUpdateLambdaCode]-> %s via the spec driver", fnArn)
	}
}

// Lambda invoke (cross-account union) is generated through the scan driver. A
// same-account IAM grant (no resource policy → IAM-only path) must still surface
// the invoke edge, proving the union scan path is wired through LambdaEdges.
func TestLambdaInvokeViaScanDriver(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	fnArn := "arn:aws:lambda:us-east-1:111122223333:function:worker"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
	})
	store.IngestLambda(s, acct, &model.LambdaData{
		AccountId: acct,
		Functions: []model.LambdaFunction{{FunctionName: "worker", FunctionArn: fnArn}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range edges.LambdaEdges(s, pe) {
		if e.Start == alice && e.End == fnArn && e.Kind == graph.KindCanInvokeLambdaFunction {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alice -[AWS_CanInvokeLambdaFunction]-> %s via the scan driver", fnArn)
	}
}
