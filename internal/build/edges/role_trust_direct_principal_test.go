package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// Exact same-account Principal ARNs are permission grants, while trusting the
// account root still needs identity-side delegation. An explicit identity Deny
// remains authoritative even for an exact principal grant.
func TestRoleTrustEdgesSameAccountDirectPrincipalGrant(t *testing.T) {
	const account = "111122223333"
	directAllowed := "arn:aws:iam::111122223333:user/direct-allowed"
	directDenied := "arn:aws:iam::111122223333:user/direct-denied"
	boundaryAllowed := "arn:aws:iam::111122223333:user/boundary-allowed"
	boundaryDenied := "arn:aws:iam::111122223333:user/boundary-denied"
	boundaryUnknown := "arn:aws:iam::111122223333:user/boundary-unknown"
	trustDenied := "arn:aws:iam::111122223333:user/trust-denied"
	trustNotPrincipalDenied := "arn:aws:iam::111122223333:user/trust-not-principal-denied"
	directTarget := "arn:aws:iam::111122223333:role/direct-target"
	accountTarget := "arn:aws:iam::111122223333:role/account-target"
	allowBoundaryARN := "arn:aws:iam::111122223333:policy/allow-boundary"
	denyBoundaryARN := "arn:aws:iam::111122223333:policy/deny-boundary"
	unknownBoundaryARN := "arn:aws:iam::111122223333:policy/unknown-boundary"

	deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111122223333:role/direct-target"}]}`
	directTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:user/direct-allowed","arn:aws:iam::111122223333:user/direct-denied","arn:aws:iam::111122223333:user/boundary-allowed","arn:aws:iam::111122223333:user/boundary-denied","arn:aws:iam::111122223333:user/boundary-unknown","arn:aws:iam::111122223333:user/trust-denied","arn:aws:iam::111122223333:user/trust-not-principal-denied"]},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:user/trust-denied"},"Action":"sts:AssumeRole"},{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/direct-allowed"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalArn":"arn:aws:iam::111122223333:user/trust-not-principal-denied"}}}]}`
	accountTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`
	boundary := func(arn, name, document string) model.PolicyDetail {
		return model.PolicyDetail{
			Arn: arn, PolicyName: name, DefaultVersionId: "v1",
			PolicyVersions: []model.PolicyVersion{{VersionId: "v1", IsDefaultVersion: true, Document: document}},
		}
	}
	allowBoundary := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111122223333:role/direct-target"}]}`
	denyBoundary := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetBucketLocation","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(account, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: directAllowed, UserName: "direct-allowed"},
			{Arn: directDenied, UserName: "direct-denied", UserPolicyList: []model.InlinePolicy{{PolicyName: "deny", PolicyDocument: deny}}},
			{Arn: boundaryAllowed, UserName: "boundary-allowed", PermissionsBoundary: &model.PermBoundary{PermissionsBoundaryArn: allowBoundaryARN}},
			{Arn: boundaryDenied, UserName: "boundary-denied", PermissionsBoundary: &model.PermBoundary{PermissionsBoundaryArn: denyBoundaryARN}},
			{Arn: boundaryUnknown, UserName: "boundary-unknown", PermissionsBoundary: &model.PermBoundary{PermissionsBoundaryArn: unknownBoundaryARN}},
			{Arn: trustDenied, UserName: "trust-denied"},
			{Arn: trustNotPrincipalDenied, UserName: "trust-not-principal-denied"},
		},
		RoleDetailList: []model.RoleDetail{
			{Arn: directTarget, RoleName: "direct-target", AssumeRolePolicyDocument: directTrust},
			{Arn: accountTarget, RoleName: "account-target", AssumeRolePolicyDocument: accountTrust},
		},
		Policies: []model.PolicyDetail{
			boundary(allowBoundaryARN, "allow-boundary", allowBoundary),
			boundary(denyBoundaryARN, "deny-boundary", denyBoundary),
		},
	})
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	found := map[[2]string]bool{}
	for _, edge := range edges.RoleTrustEdges(s, pe) {
		if edge.Kind == graph.KindCanAssumeRole {
			found[[2]string{edge.Start, edge.End}] = true
		}
	}
	for _, p := range []string{directAllowed, boundaryAllowed} {
		if !found[[2]string{p, directTarget}] {
			t.Fatalf("complete exact same-account trust path was omitted for %s", p)
		}
	}
	for _, p := range []string{directDenied, boundaryDenied, boundaryUnknown, trustDenied, trustNotPrincipalDenied} {
		if found[[2]string{p, directTarget}] {
			t.Fatalf("constrained exact-principal trust incorrectly emitted for %s", p)
		}
	}
	if found[[2]string{directAllowed, accountTarget}] {
		t.Fatal("account-root trust incorrectly bypassed identity-side delegation")
	}
}
