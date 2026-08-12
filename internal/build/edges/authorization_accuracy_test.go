package edges

import (
	"encoding/json"
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func hasAccuracyEdge(edges []*graph.Edge, start, end string, kind graph.EdgeKind) bool {
	for _, edge := range edges {
		if edge.Start == start && edge.End == end && edge.Kind == kind {
			return true
		}
	}
	return false
}

func TestServiceLinkedRoleManipulationPositiveAndNegative(t *testing.T) {
	accountID := "111122223333"
	principal := "arn:aws:iam::" + accountID + ":user/operator"
	ordinary := "arn:aws:iam::" + accountID + ":role/ordinary"
	linked := "arn:aws:iam::" + accountID + ":role/aws-service-role/eks.amazonaws.com/linked"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:AttachRolePolicy","iam:PutRolePolicy","iam:DeleteRolePolicy","iam:DetachRolePolicy","iam:PutRolePermissionsBoundary","iam:DeleteRolePermissionsBoundary","iam:DeleteRole"],"Resource":"*"}]}`
	s := store.New()
	s.AddAuthDetails(accountID, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: principal, UserName: "operator", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
		RoleDetailList: []model.RoleDetail{{Arn: ordinary, RoleName: "ordinary"}, {Arn: linked, RoleName: "linked"}},
	})
	pe, _ := eval.NewPolicyEvaluator(s)
	edges := IAMManipulationEdges(s, pe)
	if !hasAccuracyEdge(edges, principal, ordinary, graph.KindCanAttachRolePolicy) {
		t.Fatal("ordinary-role positive control missing")
	}
	for _, kind := range []graph.EdgeKind{graph.KindCanAttachRolePolicy, graph.KindCanPutRolePolicy, graph.KindCanDeleteRolePolicy, graph.KindCanDetachRolePolicy, graph.KindCanPutRolePermissionsBoundary, graph.KindCanDeleteRolePermissionsBoundary} {
		if hasAccuracyEdge(edges, principal, linked, kind) {
			t.Fatalf("service-linked-role negative control emitted %s", kind)
		}
	}
}

func TestLambdaAccountDelegationAndNotSelectors(t *testing.T) {
	accountID := "111122223333"
	delegated := "arn:aws:iam::" + accountID + ":user/delegated"
	direct := "arn:aws:iam::" + accountID + ":user/direct"
	function := "arn:aws:lambda:us-east-1:" + accountID + ":function:target"
	policy := map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::" + accountID + ":root"}, "Action": "lambda:InvokeFunction", "Resource": function},
		map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": direct}, "NotAction": "lambda:DeleteFunction", "NotResource": "arn:aws:lambda:us-east-1:" + accountID + ":function:excluded"},
	}}
	raw, _ := json.Marshal(policy)
	s := store.New()
	s.AddAuthDetails(accountID, &model.AuthDetails{UserDetailList: []model.UserDetail{{Arn: delegated, UserName: "delegated"}, {Arn: direct, UserName: "direct"}}})
	store.IngestLambda(s, accountID, &model.LambdaData{Functions: []model.LambdaFunction{{FunctionArn: function, FunctionName: "target", Region: "us-east-1", Policy: string(raw)}}})
	pe, _ := eval.NewPolicyEvaluator(s)
	edges := LambdaEdges(s, pe)
	if !hasAccuracyEdge(edges, direct, function, graph.KindCanInvokeLambdaFunction) {
		t.Fatal("exact-direct and NotAction positive control missing")
	}
	if hasAccuracyEdge(edges, delegated, function, graph.KindCanInvokeLambdaFunction) {
		t.Fatal("account delegation negative control emitted without identity Allow")
	}
}

func TestKMSDirectGrantAndNegatedSelectors(t *testing.T) {
	accountID := "111122223333"
	allowed := "arn:aws:iam::" + accountID + ":user/kms-allowed"
	denied := "arn:aws:iam::" + accountID + ":user/kms-denied"
	key := "arn:aws:kms:us-east-1:" + accountID + ":key/direct"
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"` + denied + `"},"NotAction":"kms:ScheduleKeyDeletion","NotResource":"arn:aws:kms:us-east-1:` + accountID + `:key/excluded"}]}`
	s := store.New()
	s.AddAuthDetails(accountID, &model.AuthDetails{UserDetailList: []model.UserDetail{{Arn: allowed, UserName: "allowed"}, {Arn: denied, UserName: "denied"}}})
	store.IngestKMS(s, accountID, &model.KMSData{Keys: []model.KMSKey{{KeyId: "direct", Arn: key, Region: "us-east-1", KeyManager: "CUSTOMER", KeyState: "Enabled", KeyPolicy: []byte(policy), KeyPolicyKnown: true}}})
	pe, _ := eval.NewPolicyEvaluator(s)
	ctx := kmsDirectRequestContext(pe, key, allowed, "kms:Decrypt")
	parsed := kmsCompileKeyPolicy(s.Account(accountID).KMSKeyList()[0], accountID)
	if result := kmsCheckKeyPolicyAllows(parsed, key, allowed, "kms:Decrypt", ctx); !result.Allowed {
		t.Fatalf("KMS resource policy direct check = %+v", result)
	}
	if result := kmsCanPerformAction(pe, s.Account(accountID).KMSKeyList()[0], parsed, allowed, "kms:Decrypt"); !result.Allowed {
		t.Fatalf("KMS full direct check = %+v", result)
	}
	edges := KMSEdges(s, pe)
	if !hasAccuracyEdge(edges, allowed, key, graph.KindKMSKeyRead) {
		t.Fatal("KMS NotPrincipal/NotAction/NotResource positive control missing")
	}
	if hasAccuracyEdge(edges, denied, key, graph.KindKMSKeyRead) {
		t.Fatal("KMS NotPrincipal negative control emitted")
	}
}
