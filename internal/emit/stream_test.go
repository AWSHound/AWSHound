package emit_test

import (
	"bytes"
	"testing"

	"github.com/AWSHound/AWSHound/internal/emit"
	"github.com/AWSHound/AWSHound/internal/graph"
)

// StreamGraphFromBuilt reads a built.json (raw ARN ids) and writes the final
// OpenGraph JSON (encoded ids) by streaming — producing bytes identical to
// WriteGraph(ReadBuilt(...)), but without materializing the whole graph. This
// lets the `all` command emit graph.json straight from the streamed built.json.
func TestStreamGraphFromBuiltMatchesWriteGraph(t *testing.T) {
	nodes := []*graph.Node{
		graph.NewNode("arn:aws:iam::111:user/a", graph.KindUser).Set("name", "a"),
		graph.NewNode("arn:aws:s3:::b/obj", graph.KindPolicy).Set("k", "v"),
	}
	edges := []*graph.Edge{
		graph.NewEdge("arn:aws:iam::111:user/a", "arn:aws:s3:::b/obj", "AWS_CanGetObject").Set("is_traversable", true),
	}

	// Build the built.json input.
	var built bytes.Buffer
	if err := graph.WriteBuilt(&built, nodes, edges); err != nil {
		t.Fatal(err)
	}

	// Reference: WriteGraph on the same nodes/edges.
	var ref bytes.Buffer
	if err := emit.WriteGraph(&ref, nodes, edges); err != nil {
		t.Fatal(err)
	}

	// Streaming: read built.json, write graph.json.
	var got bytes.Buffer
	if err := emit.StreamGraphFromBuilt(bytes.NewReader(built.Bytes()), &got); err != nil {
		t.Fatal(err)
	}

	if got.String() != ref.String() {
		t.Fatalf("streamed graph differs:\n stream: %s\n ref:    %s", got.String(), ref.String())
	}
}
