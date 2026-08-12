package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// KMS's gated constituents are generated through the scan driver (EvalFunc wrapping
// kmsCanPerformAction). A customer key whose policy delegates to IAM must surface
// the identity-granted kms:Decrypt edge. KMS had no test.
func TestKMSConstituentViaScanDriver(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	keyArn := "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	// Identity grants Decrypt; the key policy enables IAM delegation for the account.
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}`
	keyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
	})
	store.IngestKMS(s, acct, &model.KMSData{
		AccountId: acct,
		Keys: []model.KMSKey{{
			KeyId: "abcd-1234", Arn: keyArn, KeyManager: "CUSTOMER", KeyState: "Enabled",
			KeyPolicy: []byte(keyPolicy),
		}},
	})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range edges.KMSEdges(s, pe) {
		if e.Start == alice && e.End == keyArn && e.Kind == graph.KindCanDecryptKMSKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alice -[AWS_CanDecryptKMSKey]-> %s via the scan driver", keyArn)
	}
}
