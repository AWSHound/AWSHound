package build

import (
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// EKSNodes emits the account's AWS_EKSCluster and AWS_EKSNodeGroup nodes — the Go port
// of AWSHound's EKSClusterNodeParser and EKSNodeGroupNodeParser (core/graph/nodes/eks.py).
// One node per cluster and per managed node group, keyed by the real ARN AWS returned,
// with the exact property set (and insertion order) the Python parsers produce.
// Clusters missing an arn or name are skipped, as are node groups missing a nodegroupArn
// or nodegroupName (the Python parsers' early continue). EKSClusterList / EKSNodeGroupList
// return resources in ARN order, so the output is diff-stable.
//
// The "name" is "<account>:<resource name>". The tags property is a JSON-encoded string,
// present only when non-empty (the Python `if tags:` guard); instance_types is always
// emitted as a JSON array string (the Python json.dumps of instanceTypes, "[]" when
// empty). Both use Go's compact separators, the same convention as the other builders.
func EKSNodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	var nodes []*graph.Node

	// AWS_EKSCluster nodes (EKSClusterNodeParser).
	for _, c := range a.EKSClusterList() {
		if c.Arn == "" || c.Name == "" {
			continue
		}
		n := graph.NewNode(c.Arn, graph.KindEKSCluster)
		n.Set("name", accountID+":"+c.Name)
		n.Set("arn", c.Arn)
		n.Set("account_id", accountID)
		n.Set("region", c.Region)
		n.Set("status", c.Status)
		n.Set("version", c.Version)
		n.Set("role_arn", c.RoleArn)
		n.Set("endpoint", c.Endpoint)
		n.Set("platform_version", c.PlatformVersion)
		n.Set("oidc_issuer", c.Identity.Oidc.Issuer)
		if len(c.Tags) > 0 {
			n.Set("tags", jsonProp(c.Tags))
		}
		nodes = append(nodes, n)
	}

	// AWS_EKSNodeGroup nodes (EKSNodeGroupNodeParser).
	for _, ng := range a.EKSNodeGroupList() {
		if ng.NodegroupArn == "" || ng.NodegroupName == "" {
			continue
		}
		// instance_types is emitted unconditionally; a nil slice must serialize as
		// "[]", matching the Python instanceTypes default of [].
		instanceTypes := ng.InstanceTypes
		if instanceTypes == nil {
			instanceTypes = []string{}
		}
		n := graph.NewNode(ng.NodegroupArn, graph.KindEKSNodeGroup)
		n.Set("name", accountID+":"+ng.NodegroupName)
		n.Set("arn", ng.NodegroupArn)
		n.Set("account_id", accountID)
		n.Set("region", ng.Region)
		n.Set("cluster_name", ng.ClusterName)
		n.Set("node_role", ng.NodeRole)
		n.Set("status", ng.Status)
		n.Set("ami_type", ng.AmiType)
		n.Set("capacity_type", ng.CapacityType)
		n.Set("instance_types", jsonProp(instanceTypes))
		n.Set("min_size", ng.ScalingConfig.MinSize)
		n.Set("max_size", ng.ScalingConfig.MaxSize)
		n.Set("desired_size", ng.ScalingConfig.DesiredSize)
		if len(ng.Tags) > 0 {
			n.Set("tags", jsonProp(ng.Tags))
		}
		nodes = append(nodes, n)
	}

	return nodes
}
