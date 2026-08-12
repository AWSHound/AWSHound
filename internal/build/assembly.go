package build

import (
	"encoding/json"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// jsonProp serializes a value to a compact JSON string for a node property — the
// shared stand-in for every service node parser's json.dumps of tags/aliases/
// grants/security_groups/etc. (Go's compact separators). It returns "" on error so
// a caller under an `if len(...) > 0` guard simply omits the property.
func jsonProp(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// nodeParsers is every service's node parser. AccountNodes runs them all.
var nodeParsers = []func(*store.Account) []*graph.Node{
	AccountRootNode,
	IAMNodes,
	OrganizationsNodes,
	S3Nodes,
	KMSNodes,
	SSMNodes,
	EC2Nodes,
	LambdaNodes,
	CloudFormationNodes,
	EKSNodes,
}

// AccountNodes runs every service node parser over an account and merges nodes
// that share an id. Parsers whose service has no data return nothing.
func AccountNodes(a *store.Account) []*graph.Node {
	var all []*graph.Node
	for _, parse := range nodeParsers {
		all = append(all, parse(a)...)
	}
	// Global node enrichment, ported from builder.py:483-488: every node in an
	// account carries collected=true (unless a parser already set it, e.g.
	// referenced-only federation providers) and environmentid pointing at the
	// account's encoded root ARN — BHE uses environmentid to group a tenant.
	envID := graph.EncodeID("arn:aws:iam::" + a.ID + ":root")
	for _, n := range all {
		if !n.Props.Has("collected") {
			n.Set("collected", true)
		}
		if !n.Props.Has("environmentid") {
			n.Set("environmentid", envID)
		}
	}
	return MergeNodes(all)
}

// MergeNodes unions nodes that share an id. BHE's OpenGraph ingest merges nodes
// by id, but emit.WriteGraph does not dedup, and different services legitimately
// emit the same id (e.g. IAM and Organizations both produce an AWS_Account node
// for the same account). Kinds are unioned (capped at BHE's 3); properties are
// merged with later-wins; first-appearance order is preserved for diff stability.
func MergeNodes(nodes []*graph.Node) []*graph.Node {
	byID := make(map[string]*graph.Node, len(nodes))
	order := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ex, ok := byID[n.ID]
		if !ok {
			byID[n.ID] = n
			order = append(order, n.ID)
			continue
		}
		for _, k := range n.Kinds {
			if len(ex.Kinds) >= 3 {
				break
			}
			ex.AddKind(k) // dedups; guarded above so it never exceeds 3
		}
		for _, key := range n.Props.Keys() {
			ex.Props.Set(key, n.Props.Get(key))
		}
	}
	out := make([]*graph.Node, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}
