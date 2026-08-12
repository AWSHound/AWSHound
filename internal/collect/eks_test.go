package collect

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func TestEKSConvertNodeGroupPreservesManagedResources(t *testing.T) {
	nodeGroup := eksConvertNodeGroup(&ekstypes.Nodegroup{
		NodegroupName: aws.String("nodes"),
		Resources: &ekstypes.NodegroupResources{
			AutoScalingGroups:         []ekstypes.AutoScalingGroup{{Name: aws.String("eks-managed-asg")}},
			RemoteAccessSecurityGroup: aws.String("sg-1234"),
		},
	}, "us-east-1")

	if nodeGroup.Resources == nil || len(nodeGroup.Resources.AutoScalingGroups) != 1 ||
		nodeGroup.Resources.AutoScalingGroups[0].Name != "eks-managed-asg" ||
		nodeGroup.Resources.RemoteAccessSecurityGroup != "sg-1234" {
		t.Fatalf("node-group managed resources were not converted: %#v", nodeGroup.Resources)
	}
}
