package edges_test

import (
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/build"
	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func TestKMSEdgesRequireUsableKeyState(t *testing.T) {
	const (
		accountID         = "111122223333"
		principalArn      = "arn:aws:iam::111122223333:user/operator"
		enabledKeyArn     = "arn:aws:kms:us-east-1:111122223333:key/enabled"
		pendingKeyArn     = "arn:aws:kms:us-east-1:111122223333:key/pending"
		pendingReplicaArn = "arn:aws:kms:us-east-1:111122223333:key/pending-replica"
	)
	identityPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`
	keyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"}]}`

	key := func(arn, state string) model.KMSKey {
		return model.KMSKey{
			KeyId: arn[strings.LastIndexByte(arn, '/')+1:], Arn: arn, KeyManager: "CUSTOMER",
			KeyState: state, Enabled: true, KeyPolicy: []byte(keyPolicy), KeyPolicyKnown: true,
		}
	}
	storeInstance := store.New()
	storeInstance.AddAuthDetails(accountID, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{
			Arn: principalArn, UserName: "operator",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "kms-admin", PolicyDocument: identityPolicy}},
		}},
	})
	store.IngestKMS(storeInstance, accountID, &model.KMSData{AccountId: accountID, Keys: []model.KMSKey{
		key(enabledKeyArn, "Enabled"), key(pendingKeyArn, "PendingDeletion"),
		key(pendingReplicaArn, "PendingReplicaDeletion"),
	}})

	if nodes := build.KMSNodes(storeInstance.Account(accountID)); len(nodes) != 3 {
		t.Fatalf("pending-deletion keys must remain nodes; got %d KMS nodes", len(nodes))
	}
	evaluator, err := eval.NewPolicyEvaluator(storeInstance)
	if err != nil {
		t.Fatal(err)
	}
	var enabledEdge *graph.Edge
	for _, edge := range edges.KMSEdges(storeInstance, evaluator) {
		switch edge.End {
		case pendingKeyArn, pendingReplicaArn:
			t.Errorf("unusable key received %s from %s", edge.Kind, edge.Start)
		case enabledKeyArn:
			enabledEdge = edge
		}
	}
	if enabledEdge == nil {
		t.Fatal("enabled key with identical policies received no KMS capability")
	}
	allowSources, _ := enabledEdge.Props.Get("allow_sources").(string)
	if !strings.Contains(allowSources, "KeyPolicy/0") {
		t.Fatalf("enabled edge omitted the authorizing key policy: %q", allowSources)
	}
}

func TestAWSManagedKMSServiceConditionDoesNotBecomeDirectEdge(t *testing.T) {
	const (
		accountID    = "111122223333"
		principalArn = "arn:aws:iam::111122223333:user/operator"
		keyArn       = "arn:aws:kms:us-east-1:111122223333:key/aws-managed-ebs"
	)
	identityPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`
	keyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*","Condition":{"StringEquals":{"kms:CallerAccount":"111122223333","kms:ViaService":"ec2.us-east-1.amazonaws.com"}}}]}`

	storeInstance := store.New()
	storeInstance.AddAuthDetails(accountID, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{
			Arn: principalArn, UserName: "operator",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "kms-admin", PolicyDocument: identityPolicy}},
		}},
	})
	store.IngestKMS(storeInstance, accountID, &model.KMSData{AccountId: accountID, Keys: []model.KMSKey{
		{KeyId: "aws-managed-ebs", Arn: keyArn, KeyManager: "AWS", KeyState: "Enabled", Enabled: true, KeyPolicy: []byte(keyPolicy), KeyPolicyKnown: true},
		{KeyId: "unknown-policy", Arn: "arn:aws:kms:us-east-1:111122223333:key/unknown-policy", KeyManager: "AWS", KeyState: "Enabled", Enabled: true},
	}})
	evaluator, err := eval.NewPolicyEvaluator(storeInstance)
	if err != nil {
		t.Fatal(err)
	}
	for _, edge := range edges.KMSEdges(storeInstance, evaluator) {
		if strings.HasPrefix(edge.End, "arn:aws:kms:") {
			t.Errorf("AWS-managed key without a direct authorization proof received %s to %s", edge.Kind, edge.End)
		}
	}
}

func TestEKSManagedResourceConditionLimitsTermination(t *testing.T) {
	const (
		accountID             = "111122223333"
		serviceRoleArn        = "arn:aws:iam::111122223333:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS"
		managedInstanceArn    = "arn:aws:ec2:us-east-1:111122223333:instance/i-managed"
		standaloneInstanceArn = "arn:aws:ec2:us-east-1:111122223333:instance/i-standalone"
	)
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:TerminateInstances","Resource":"*","Condition":{"StringEquals":{"ec2:ManagedResourceOperator":"eks.amazonaws.com"}}}]}`

	storeInstance := store.New()
	storeInstance.AddAuthDetails(accountID, &model.AuthDetails{RoleDetailList: []model.RoleDetail{{
		Arn: serviceRoleArn, RoleName: "AWSServiceRoleForAmazonEKS",
		RolePolicyList: []model.InlinePolicy{{PolicyName: "eks-service", PolicyDocument: policy}},
	}}})
	store.IngestEKS(storeInstance, accountID, &model.EKSData{AccountId: accountID, NodeGroups: []model.EKSNodeGroup{{
		NodegroupArn: "arn:aws:eks:us-east-1:111122223333:nodegroup/cluster/nodes/uuid",
		ClusterName:  "cluster", NodegroupName: "nodes",
		Resources: &model.EKSNodeGroupResources{AutoScalingGroups: []model.EKSAutoScalingGroup{{Name: "eks-managed-asg"}}},
	}}})
	store.IngestEC2(storeInstance, accountID, &model.EC2Data{AccountId: accountID, Instances: []model.EC2Instance{
		{InstanceId: "i-managed", Region: "us-east-1", State: model.EC2State{Name: "running"}, Tags: []model.Tag{{Key: "aws:autoscaling:groupName", Value: "eks-managed-asg"}}},
		{InstanceId: "i-standalone", Region: "us-east-1", State: model.EC2State{Name: "running"}, Tags: []model.Tag{}},
	}})
	evaluator, err := eval.NewPolicyEvaluator(storeInstance)
	if err != nil {
		t.Fatal(err)
	}
	var foundManaged, foundStandalone bool
	for _, edge := range edges.EC2Edges(storeInstance, evaluator) {
		if edge.Start != serviceRoleArn || edge.Kind != graph.KindCanTerminateInstances {
			continue
		}
		foundManaged = foundManaged || edge.End == managedInstanceArn
		foundStandalone = foundStandalone || edge.End == standaloneInstanceArn
	}
	if !foundManaged || foundStandalone {
		t.Fatalf("termination edges: managed=%t standalone=%t; want true/false", foundManaged, foundStandalone)
	}
}

func TestStructuralContainsIncludesS3BucketsAndObjects(t *testing.T) {
	const accountID = "111122223333"
	storeInstance := store.New()
	store.IngestS3(storeInstance, accountID, &model.S3Data{AccountId: accountID, Buckets: []model.S3Bucket{
		{Name: "empty-bucket"},
		{Name: "object-bucket", Objects: []model.S3Object{{Key: "fixture.txt"}}},
	}})

	edgeSet := map[string]bool{}
	for _, edge := range edges.StructuralEdges(storeInstance, nil) {
		edgeSet[edge.Start+"|"+string(edge.Kind)+"|"+edge.End] = true
	}
	for _, expected := range []string{
		"arn:aws:iam::111122223333:root|AWS_Contains|arn:aws:s3:::empty-bucket",
		"arn:aws:iam::111122223333:root|AWS_Contains|arn:aws:s3:::object-bucket",
		"arn:aws:s3:::object-bucket|AWS_Contains|arn:aws:s3:::object-bucket/fixture.txt",
	} {
		if !edgeSet[expected] {
			t.Errorf("missing containment edge %s", expected)
		}
	}
}
