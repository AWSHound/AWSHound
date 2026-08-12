package build

import (
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// CloudFormationNodes emits the account's AWS_CloudFormationStack and
// AWS_CloudFormationStackSet nodes — the Go port of AWSHound's
// CloudFormationStackNodeParser and CloudFormationStackSetNodeParser
// (core/graph/nodes/cloudformation.py). Stacks are emitted first (in StackId order),
// then StackSets (in StackSetARN order), each with the exact property set and
// insertion order the Python parsers produce. A stack with no StackId / a StackSet
// with no StackSetARN is skipped, mirroring the Python `if not arn: continue`.
//
// The "name" is "<account>:<stack or stackset name>". A stack's region falls back to
// us-east-1 when absent (the Python parser's stack.get("Region", cf_data.get("Region",
// "us-east-1")) chain; the collector always stamps the region, so this only affects
// re-ingested captures). A StackSet's region has no fallback — empty stays empty,
// matching stack_set.get("Region", ""). The "tags" property is a compact-JSON string
// emitted only when the stack has tags (the Python `if tags:` guard).
func CloudFormationNodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	var nodes []*graph.Node

	for _, stack := range a.CloudFormationStackList() {
		stackArn := stack.StackId
		if stackArn == "" {
			continue
		}
		region := stack.Region
		if region == "" {
			region = "us-east-1"
		}

		n := graph.NewNode(stackArn, graph.KindCloudFormationStack)
		n.Set("name", accountID+":"+stack.StackName)
		n.Set("arn", stackArn)
		n.Set("account_id", accountID)
		n.Set("region", region)
		n.Set("stack_status", stack.StackStatus)
		n.Set("role_arn", stack.RoleARN)

		if len(stack.Tags) > 0 {
			n.Set("tags", jsonProp(stack.Tags))
		}

		nodes = append(nodes, n)
	}

	for _, ss := range a.CloudFormationStackSetList() {
		arn := ss.StackSetARN
		if arn == "" {
			continue
		}

		n := graph.NewNode(arn, graph.KindCloudFormationStackSet)
		n.Set("name", accountID+":"+ss.StackSetName)
		n.Set("arn", arn)
		n.Set("account_id", accountID)
		n.Set("region", ss.Region)
		n.Set("permission_model", ss.PermissionModel)
		n.Set("status", ss.Status)
		n.Set("administration_role_arn", ss.AdministrationRoleARN)
		n.Set("execution_role_name", ss.ExecutionRoleName)

		nodes = append(nodes, n)
	}

	return nodes
}
