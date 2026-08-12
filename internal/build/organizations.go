// Package build turns ingested store data into OpenGraph nodes — the Go port of
// AWSHound's core/graph/nodes/* parsers. Each <svc>.go emits one service's nodes
// with their exact property set; the caller assembles and dedups them by ID before
// emit.WriteGraph serializes the graph.
package build

import (
	"sort"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// OrganizationsNodes emits the AWS Organizations nodes carried on the account the
// org data was ingested on: one AWS_Organization, one AWS_Account per member
// account (decorated with its org membership), and one node per SCP and RCP. It is
// the combined port of the organization.py, account.py, and policies.py node
// parsers (the SCP/RCP halves of policies.py).
//
// Nodes are ordered deterministically (accounts and policies by ARN) so repeated
// runs produce diff-stable output.
func OrganizationsNodes(a *store.Account) []*graph.Node {
	var nodes []*graph.Node

	root := a.OrganizationRecord()
	if root != nil {
		org := root.Organization

		// AWSOrganization node (organization.py). Skipped without an ARN, matching
		// the Python parser's early return.
		if org.Arn != "" {
			nodes = append(nodes, graph.NewNode(org.Arn, graph.KindOrganization).
				Set("name", org.Id).
				Set("org_id", org.Id).
				Set("arn", org.Arn).
				Set("master_account_id", org.MasterAccountId).
				Set("feature_set", org.FeatureSet))
		}

		// AWSAccount node per member account (account.py). Every account known to
		// the org is a member, so it is decorated with org_id / org_path /
		// management_account_id, plus is_management_account marking the one account
		// that is the org's management account.
		for _, accountID := range sortedKeys(root.AccountOrgPaths) {
			arn := "arn:aws:iam::" + accountID + ":root"
			node := graph.NewNode(arn, graph.KindAccount).
				Set("account_id", accountID).
				Set("arn", arn)
			// This is the same value the member's own AccountRootNode writes, since
			// Account.ResolvedName ranks the org name first and an account belongs to
			// at most one org (so no two OrgRoots name the same account). The two
			// writers agreeing is what makes the merged name independent of which
			// account merges last. Omitted when the org reported no name — see
			// setAccountName.
			setAccountName(node, root.AccountNames[accountID])
			if org.Id != "" {
				node.Set("org_id", org.Id)
			}
			if path := root.AccountOrgPaths[accountID]; path != "" {
				node.Set("org_path", path)
			}
			if org.Id != "" && org.MasterAccountId != "" {
				node.Set("management_account_id", org.MasterAccountId)
				// Emitted only under the same guard as management_account_id, and
				// only on this org path, so that a missing flag keeps its distinct
				// meaning: "no org data was collected for this account", which is
				// not the same claim as "known not to be the management account".
				// AccountRootNode never sets it.
				node.Set("is_management_account", accountID == org.MasterAccountId)
			}
			nodes = append(nodes, node)
		}
	}

	// AWSServiceControlPolicy nodes (policies.py).
	scps := a.SCPPolicyList()
	sort.Slice(scps, func(i, j int) bool { return scps[i].Arn < scps[j].Arn })
	for _, p := range scps {
		if p.Arn == "" {
			continue
		}
		nodes = append(nodes, graph.NewNode(p.Arn, graph.KindServiceControlPolicy).
			Set("name", p.Name).
			Set("policy_id", p.Id).
			Set("policy_name", p.Name).
			Set("arn", p.Arn).
			Set("content", orgPolicyContent(p.Content)).
			Set("aws_managed", p.AwsManaged))
	}

	// AWSResourceControlPolicy nodes (policies.py).
	rcps := a.RCPPolicyList()
	sort.Slice(rcps, func(i, j int) bool { return rcps[i].Arn < rcps[j].Arn })
	for _, p := range rcps {
		if p.Arn == "" {
			continue
		}
		nodes = append(nodes, graph.NewNode(p.Arn, graph.KindResourceControlPolicy).
			Set("name", p.Name).
			Set("policy_id", p.Id).
			Set("policy_name", p.Name).
			Set("arn", p.Arn).
			Set("content", orgPolicyContent(p.Content)).
			Set("aws_managed", p.AwsManaged))
	}

	return nodes
}

// orgPolicyContent mirrors the node parser's policy.get("Content", "{}") default:
// an SCP/RCP node always carries a content property, "{}" when the document is
// absent.
func orgPolicyContent(content string) string {
	if content == "" {
		return "{}"
	}
	return content
}
