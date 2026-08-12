package graph

import (
	"bytes"
	"testing"
)

// A streaming built writer (nodes then edges, one at a time) must produce bytes
// identical to WriteBuilt on the same data, so the memory-bounded build path is a
// drop-in for the accumulate-then-write path.
func TestBuiltStreamWriterMatchesWriteBuilt(t *testing.T) {
	nodes := []*Node{
		NewNode("arn:aws:iam::111:user/a", KindUser).Set("name", "a"),
		NewNode("arn:aws:s3:::b/obj", KindPolicy).Set("k", "v"),
	}
	edges := []*Edge{
		NewEdge("arn:aws:iam::111:user/a", "arn:aws:s3:::b/obj", "AWS_CanGetObject").Set("is_traversable", true),
		NewEdge("arn:aws:iam::111:user/a", "arn:aws:s3:::b", "AWS_CanListBucket"),
	}

	var ref bytes.Buffer
	if err := WriteBuilt(&ref, nodes, edges); err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	w := NewBuiltStreamWriter(&got)
	for _, n := range nodes {
		if err := w.Node(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Edges(); err != nil {
		t.Fatal(err)
	}
	for _, e := range edges {
		if err := w.Edge(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got.String() != ref.String() {
		t.Fatalf("streamed built differs from WriteBuilt:\n stream: %s\n ref:    %s", got.String(), ref.String())
	}
}

// Empty graph still yields the canonical {"nodes":[],"edges":[]}.
func TestBuiltStreamWriterEmpty(t *testing.T) {
	var got bytes.Buffer
	w := NewBuiltStreamWriter(&got)
	if err := w.Edges(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var ref bytes.Buffer
	if err := WriteBuilt(&ref, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.String() != ref.String() {
		t.Fatalf("empty streamed = %q, want %q", got.String(), ref.String())
	}
}
