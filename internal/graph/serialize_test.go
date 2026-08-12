package graph_test

import (
	"bytes"
	"testing"

	"github.com/AWSHound/AWSHound/internal/emit"
	"github.com/AWSHound/AWSHound/internal/graph"
)

// buildSample constructs a small graph exercising the property value kinds and
// ordering that must survive a built.json round-trip.
func buildSample() ([]*graph.Node, []*graph.Edge) {
	n1 := graph.NewNode("arn:aws:iam::111122223333:user/alice", graph.NodeKind("AWSUser"))
	n1.AddKind(graph.NodeKind("AWSPrincipal"))
	n1.Set("name", "alice").
		Set("enabled", true).
		Set("keycount", 2).
		Set("tags", []string{"prod", "team-a"}).
		Set("note", "")
	n2 := graph.NewNode("arn:aws:iam::111122223333:role/app", graph.NodeKind("AWSRole"))

	e := graph.NewEdge(n1.ID, n2.ID, graph.EdgeKind("AWSAssumeRole"))
	e.Set("via", "sts:AssumeRole")
	ePlain := graph.NewEdge(n2.ID, n1.ID, graph.EdgeKind("AWSMemberOf")) // no properties

	return []*graph.Node{n1, n2}, []*graph.Edge{e, ePlain}
}

func TestBuiltRoundTripIsWireStable(t *testing.T) {
	nodes, edges := buildSample()

	// Direct emit.
	var direct bytes.Buffer
	if err := emit.WriteGraph(&direct, nodes, edges); err != nil {
		t.Fatalf("direct WriteGraph: %v", err)
	}

	// process -> built.json -> emit.
	var built bytes.Buffer
	if err := graph.WriteBuilt(&built, nodes, edges); err != nil {
		t.Fatalf("WriteBuilt: %v", err)
	}
	rNodes, rEdges, err := graph.ReadBuilt(bytes.NewReader(built.Bytes()))
	if err != nil {
		t.Fatalf("ReadBuilt: %v", err)
	}
	var viaBuilt bytes.Buffer
	if err := emit.WriteGraph(&viaBuilt, rNodes, rEdges); err != nil {
		t.Fatalf("round-trip WriteGraph: %v", err)
	}

	if direct.String() != viaBuilt.String() {
		t.Errorf("round-tripped emit differs from direct emit\ndirect:\n%s\nvia built.json:\n%s", direct.String(), viaBuilt.String())
	}
}

func TestReadBuiltPreservesCountsAndKinds(t *testing.T) {
	nodes, edges := buildSample()
	var built bytes.Buffer
	if err := graph.WriteBuilt(&built, nodes, edges); err != nil {
		t.Fatal(err)
	}
	rNodes, rEdges, err := graph.ReadBuilt(&built)
	if err != nil {
		t.Fatal(err)
	}
	if len(rNodes) != len(nodes) || len(rEdges) != len(edges) {
		t.Fatalf("counts: got %d nodes %d edges, want %d/%d", len(rNodes), len(rEdges), len(nodes), len(edges))
	}
	if rNodes[0].ID != nodes[0].ID {
		t.Errorf("node id: got %q, want %q", rNodes[0].ID, nodes[0].ID)
	}
	if len(rNodes[0].Kinds) != 2 {
		t.Errorf("node kinds: got %v, want 2", rNodes[0].Kinds)
	}
	// Empty-property edge stays empty (no "properties" key emitted).
	if rEdges[1].Props.Len() != 0 {
		t.Errorf("plain edge should have no properties, got %d", rEdges[1].Props.Len())
	}
}
