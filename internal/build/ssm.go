package build

import (
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// SSMNodes emits the account's AWS_SSMParameter nodes — the Go port of AWSHound's
// SSMParameterNodeParser (core/graph/nodes/ssm.py). One node per parameter, keyed
// by its ARN, with the exact property set the Python parser produces. Parameters
// without a Name are skipped (the Python parser's early continue). SSMParameterList
// returns parameters in ARN order, so the output is diff-stable. SSM-managed
// instances are NOT nodes — they feed SSM edge processors — so they are not emitted
// here.
//
// The "name" is "<account>:<parameter name>". type/tier/version/last_modified/
// data_type carry the parser's defaults ("" / "Standard" / 1 / "" / "text") when a
// re-ingested blob omits them. description is emitted only when non-empty, and tags
// only when present (JSON-encoded, matching the Python parser's `if x:` guards and
// json.dumps — the same convention as the KMS/S3 node parsers).
func SSMNodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	var nodes []*graph.Node
	for _, p := range a.SSMParameterList() {
		if p.Name == "" {
			continue
		}

		region := p.Region
		if region == "" {
			region = "us-east-1"
		}
		arn := p.ARN
		if arn == "" {
			arn = "arn:aws:ssm:" + region + ":" + accountID + ":parameter" + p.Name
		}

		n := graph.NewNode(arn, graph.KindSSMParameter)
		n.Set("name", accountID+":"+p.Name)
		n.Set("arn", arn)
		n.Set("region", region)
		n.Set("account_id", accountID)
		n.Set("type", p.Type)
		n.Set("tier", ssmTierOr(p.Tier))
		n.Set("version", ssmVersionOr(p.Version))
		n.Set("last_modified", p.LastModifiedDate)
		n.Set("data_type", ssmDataTypeOr(p.DataType))

		if p.Description != "" {
			n.Set("description", p.Description)
		}
		if len(p.Tags) > 0 {
			n.Set("tags", jsonProp(p.Tags))
		}

		nodes = append(nodes, n)
	}

	return nodes
}

// ssmTierOr mirrors param.get("Tier", "Standard").
func ssmTierOr(tier string) string {
	if tier == "" {
		return "Standard"
	}
	return tier
}

// ssmDataTypeOr mirrors param.get("DataType", "text").
func ssmDataTypeOr(dataType string) string {
	if dataType == "" {
		return "text"
	}
	return dataType
}

// ssmVersionOr mirrors param.get("Version", 1). AWS parameter versions are always
// >= 1, so a zero value means the field was absent from a re-ingested blob and the
// parser default of 1 applies — the same zero-means-default convention the sibling
// S3 node parser uses for its string defaults.
func ssmVersionOr(version int64) int64 {
	if version == 0 {
		return 1
	}
	return version
}
