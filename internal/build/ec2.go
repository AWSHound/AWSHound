package build

import (
	"fmt"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// EC2Nodes emits the account's AWS_EC2Instance nodes — the Go port of AWSHound's
// EC2InstanceNodeParser (core/graph/nodes/ec2.py). One node per instance, keyed by its
// synthesized ARN arn:aws:ec2:<region>:<account>:instance/<id>, with the exact
// property set (and insertion order) the Python parser produces. Instances without an
// id are skipped (the Python parser's early continue), and a missing region defaults
// to us-east-1. EC2InstanceList returns instances in ARN order, so the output is
// diff-stable.
//
// The "name" is "<account>:<Name tag>", falling back to "<account>:<instance id>" when
// there is no Name tag. The tags/security_groups properties are JSON-encoded strings,
// present only when non-empty (the Python `if tags:` / `if security_groups:` guards);
// they use Go's compact separators, the same convention as the other node builders.
func EC2Nodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	var nodes []*graph.Node
	for _, inst := range a.EC2InstanceList() {
		instanceID := inst.InstanceId
		if instanceID == "" {
			continue
		}
		region := inst.Region
		if region == "" {
			region = "us-east-1"
		}
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, instanceID)

		// Name tag: the first tag whose key is "Name".
		name := ""
		for _, t := range inst.Tags {
			if t.Key == "Name" {
				name = t.Value
				break
			}
		}

		// IAM instance profile ARN, or "" when the instance has no profile.
		iamProfileARN := ""
		if inst.IamInstanceProfile != nil {
			iamProfileARN = inst.IamInstanceProfile.Arn
		}

		nameSuffix := name
		if nameSuffix == "" {
			nameSuffix = instanceID
		}

		n := graph.NewNode(arn, graph.KindEC2Instance)
		n.Set("instance_id", instanceID)
		n.Set("instance_type", inst.InstanceType)
		n.Set("arn", arn)
		n.Set("region", region)
		n.Set("account_id", accountID)
		n.Set("state", inst.State.Name)
		n.Set("vpc_id", inst.VpcId)
		n.Set("subnet_id", inst.SubnetId)
		n.Set("image_id", inst.ImageId)
		n.Set("private_ip", inst.PrivateIpAddress)
		n.Set("public_ip", inst.PublicIpAddress)
		n.Set("launch_time", inst.LaunchTime)
		n.Set("iam_instance_profile_arn", iamProfileARN)
		n.Set("name", accountID+":"+nameSuffix)

		if len(inst.Tags) > 0 {
			n.Set("tags", jsonProp(inst.Tags))
		}
		if len(inst.SecurityGroups) > 0 {
			n.Set("security_groups", jsonProp(inst.SecurityGroups))
		}

		nodes = append(nodes, n)
	}

	return nodes
}
