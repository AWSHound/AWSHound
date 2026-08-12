package edges

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// This file holds helpers shared across every edge family. They were originally
// duplicated under family-specific names (e.g. ec2SortedKeys, kmsConditionsJSON);
// the copies were byte-identical, so they live here once.

// conditionsJSON serialises the evaluator's condition list to a JSON string, or ""
// when empty — matching `json.dumps(conditions) if conditions else ""`.
func conditionsJSON(conds []map[string]any) string {
	if len(conds) == 0 {
		return ""
	}
	b, err := json.Marshal(conds)
	if err != nil {
		return ""
	}
	return string(b)
}

// sortedKeys returns a map's string keys in ascending order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// principalARNs returns an account's user ARNs (sorted) followed by its role ARNs
// (sorted) — the users+roles set of get_all_principal_arns (groups excluded).
func principalARNs(a *store.Account) []string {
	users := sortedKeys(a.Users)
	roles := sortedKeys(a.Roles)
	return append(users, roles...)
}

// filteredCandidates returns the account's user ARNs (sorted) then role ARNs
// (sorted) restricted to those in set — the users+roles that reference the action.
func filteredCandidates(acct *store.Account, set map[string]bool) []string {
	var out []string
	for _, arn := range sortedKeys(acct.Users) {
		if set[arn] {
			out = append(out, arn)
		}
	}
	for _, arn := range sortedKeys(acct.Roles) {
		if set[arn] {
			out = append(out, arn)
		}
	}
	return out
}

// isTwelveDigit reports whether s is exactly 12 ASCII digits (a bare AWS account
// id). Mirrors `entry.isdigit() and len(entry) == 12`.
func isTwelveDigit(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// accountRootARN returns an account's root ARN, the AWS_Account node id.
func accountRootARN(accountID string) string {
	return "arn:aws:iam::" + accountID + ":root"
}

// ec2InstanceARN synthesizes an instance's ARN from its region and id, defaulting
// the region to us-east-1 when absent — matching the store ingest and the EC2 node
// builder so every edge endpoint connects to a real instance node.
func ec2InstanceARN(accountID string, inst *model.EC2Instance) string {
	region := inst.Region
	if region == "" {
		region = "us-east-1"
	}
	return "arn:aws:ec2:" + region + ":" + accountID + ":instance/" + inst.InstanceId
}

// hasEBSRoot reports whether the instance's root device maps to an EBS volume — the
// block-device mapping whose DeviceName equals RootDeviceName carries an Ebs block.
func hasEBSRoot(inst *model.EC2Instance) bool {
	for i := range inst.BlockDeviceMappings {
		bdm := &inst.BlockDeviceMappings[i]
		if bdm.DeviceName == inst.RootDeviceName && bdm.Ebs != nil {
			return true
		}
	}
	return false
}

// bucketARN returns a bucket's ARN, falling back to the synthesized
// arn:aws:s3:::<name> the S3 node builder uses when the stored ARN is empty.
func bucketARN(b *model.S3Bucket) string {
	if b.Arn != "" {
		return b.Arn
	}
	return "arn:aws:s3:::" + b.Name
}

// stackARNs returns the account's CloudFormation stack ARNs, sorted.
func stackARNs(a *store.Account) []string {
	var out []string
	for _, s := range a.CloudFormationStackList() {
		if s.StackId != "" {
			out = append(out, s.StackId)
		}
	}
	sort.Strings(out)
	return out
}

// stackSetARNs returns the account's CloudFormation stack-set ARNs, sorted.
func stackSetARNs(a *store.Account) []string {
	var out []string
	for _, ss := range a.CloudFormationStackSetList() {
		if ss.StackSetARN != "" {
			out = append(out, ss.StackSetARN)
		}
	}
	sort.Strings(out)
	return out
}

// allPresent reports whether every kind is present in a pair's constituent map.
func allPresent(m map[graph.EdgeKind]*graph.Edge, kinds []graph.EdgeKind) bool {
	for _, k := range kinds {
		if m[k] == nil {
			return false
		}
	}
	return true
}

// permissionEdge builds an edge with the (is_traversable, allow_sources, conditions)
// property set, in that insertion order — matching make_edge_properties.
func permissionEdge(start, end string, kind graph.EdgeKind, traversable bool, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, end, kind)
	e.Set("is_traversable", traversable)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set("conditions", conditionsJSON(res.Conditions))
	return e
}
