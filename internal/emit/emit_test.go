package emit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/graph"
)

// TestEnvelopeParses guards the whole-artifact JSON envelope — the per-node and
// per-edge marshalers are tested in the graph package, but only a full round-trip
// catches a malformed envelope (a missing brace closing the "graph" object).
func TestEnvelopeParses(t *testing.T) {
	nodes := []*graph.Node{
		graph.NewNode("arn:aws:iam::111122223333:user/alice", graph.KindUser).Set("name", "alice"),
		graph.NewNode("arn:aws:iam::111122223333:role/admin", graph.KindRole),
	}
	edges := []*graph.Edge{
		graph.NewEdge("arn:aws:iam::111122223333:role/admin",
			"arn:aws:iam::111122223333:user/alice", graph.KindTrustedBy).Set("is_traversable", false),
	}

	var buf bytes.Buffer
	if err := WriteGraph(&buf, nodes, edges); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Graph struct {
			Nodes []map[string]any `json:"nodes"`
			Edges []map[string]any `json:"edges"`
		} `json:"graph"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("envelope did not parse: %v\n%s", err, buf.String())
	}
	if len(doc.Graph.Nodes) != 2 || len(doc.Graph.Edges) != 1 {
		t.Fatalf("counts wrong: %d nodes, %d edges", len(doc.Graph.Nodes), len(doc.Graph.Edges))
	}
	if doc.Metadata["source_kind"] != "AWS" {
		t.Fatalf("metadata.source_kind = %v, want AWS", doc.Metadata["source_kind"])
	}
	// Terminal id encoding: no raw ARN colons survive in emitted ids.
	if strings.Contains(doc.Graph.Nodes[0]["id"].(string), ":") {
		t.Fatalf("node id not colon-encoded: %v", doc.Graph.Nodes[0]["id"])
	}
	if strings.Contains(doc.Graph.Edges[0]["start"].(map[string]any)["value"].(string), ":") {
		t.Fatal("edge start not colon-encoded")
	}
}
