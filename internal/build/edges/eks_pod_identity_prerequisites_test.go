package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func TestEKSPodIdentityAssociationRequiresPassRoleAndClusterControl(t *testing.T) {
	const (
		account     = "111122223333"
		clusterName = "fixture"
		clusterARN  = "arn:aws:eks:us-east-1:111122223333:cluster/fixture"
		roleARN     = "arn:aws:iam::111122223333:role/pod-identity"
	)
	principal := func(name string) string { return "arn:aws:iam::111122223333:user/" + name }
	existingComplete := principal("existing-complete")
	selfAdminComplete := principal("self-admin-complete")
	noPassRole := principal("no-pass-role")
	noClusterControl := principal("no-cluster-control")
	wrongPassedToService := principal("wrong-passed-to-service")
	wrongAccessPolicy := principal("wrong-access-policy")

	createAssociation := `{"Effect":"Allow","Action":"eks:CreatePodIdentityAssociation","Resource":"*"}`
	createAccess := `{"Effect":"Allow","Action":["eks:CreateAccessEntry","eks:AssociateAccessPolicy"],"Resource":"*"}`
	associateViewOnly := `{"Effect":"Allow","Action":"eks:AssociateAccessPolicy","Resource":"*","Condition":{"StringEquals":{"eks:policyArn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"}}}`
	passPods := `{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/pod-identity","Condition":{"StringEquals":{"iam:PassedToService":"pods.eks.amazonaws.com"}}}`
	passEC2 := `{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/pod-identity","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}`
	policy := func(name string, statements ...string) model.InlinePolicy {
		doc := `{"Version":"2012-10-17","Statement":[`
		for i, statement := range statements {
			if i > 0 {
				doc += ","
			}
			doc += statement
		}
		doc += "]}"
		return model.InlinePolicy{PolicyName: name, PolicyDocument: doc}
	}

	s := store.New()
	s.AddAuthDetails(account, &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: existingComplete, UserName: "existing-complete", UserPolicyList: []model.InlinePolicy{policy("complete", createAssociation, passPods)}},
			{Arn: selfAdminComplete, UserName: "self-admin-complete", UserPolicyList: []model.InlinePolicy{policy("complete", createAssociation, passPods, createAccess)}},
			{Arn: noPassRole, UserName: "no-pass-role", UserPolicyList: []model.InlinePolicy{policy("no-pass", createAssociation)}},
			{Arn: noClusterControl, UserName: "no-cluster-control", UserPolicyList: []model.InlinePolicy{policy("no-cluster", createAssociation, passPods)}},
			{Arn: wrongPassedToService, UserName: "wrong-passed-to-service", UserPolicyList: []model.InlinePolicy{policy("wrong-service", createAssociation, passEC2)}},
			{Arn: wrongAccessPolicy, UserName: "wrong-access-policy", UserPolicyList: []model.InlinePolicy{policy("wrong-access-policy", createAssociation, passPods, associateViewOnly)}},
		},
		RoleDetailList: []model.RoleDetail{{
			Arn: roleARN, RoleName: "pod-identity",
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}]}`,
		}},
	})
	adminEntry := func(p string) model.EKSAccessEntry {
		return model.EKSAccessEntry{
			ClusterName: clusterName, PrincipalArn: p, Type: "STANDARD",
			AccessPolicies: []model.EKSAssociatedAccessPolicy{{
				PolicyArn:   "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
				AccessScope: model.EKSAccessScope{Type: "cluster"},
			}},
		}
	}
	store.IngestEKS(s, account, &model.EKSData{
		AccountId: account,
		Clusters:  []model.EKSCluster{{Arn: clusterARN, Name: clusterName, Region: "us-east-1"}},
		AccessEntries: []model.EKSAccessEntry{
			adminEntry(existingComplete), adminEntry(noPassRole), adminEntry(wrongPassedToService),
		},
	})
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, edge := range edges.EKSEdges(s, pe) {
		if edge.Kind == graph.KindCanCreateEKSPodIdentityAssociation && edge.End == roleARN {
			found[edge.Start] = true
		}
	}
	if !found[existingComplete] || !found[selfAdminComplete] {
		t.Fatalf("complete Pod Identity paths missing: %+v", found)
	}
	for _, p := range []string{noPassRole, noClusterControl, wrongPassedToService, wrongAccessPolicy} {
		if found[p] {
			t.Fatalf("incomplete Pod Identity path emitted for %s", p)
		}
	}
}
