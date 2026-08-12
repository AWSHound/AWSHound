package graph

import "testing"

// These tests pin the exact wire contract ported from AWSHound's core/graph/types.py.
// They are byte-level so any drift from the OpenGraph shape fails loudly.

func TestNodeWireShape(t *testing.T) {
	n := NewNode("arn:aws:iam::123456789012:user/alice", KindUser).Set("name", "alice")
	got, err := n.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"arn:aws:iam::123456789012:user/alice","kinds":["AWS_User"],"properties":{"name":"alice"}}`
	if string(got) != want {
		t.Fatalf("node mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestNodeEmptyPropertiesAlwaysPresent(t *testing.T) {
	n := NewNode("x", KindRole)
	got, _ := n.MarshalJSON()
	want := `{"id":"x","kinds":["AWS_Role"],"properties":{}}`
	if string(got) != want {
		t.Fatalf("got=%s want=%s", got, want)
	}
}

func TestNodePropertyInsertionOrder(t *testing.T) {
	n := NewNode("x", KindUser).Set("z", 1).Set("a", 2).Set("m", 3)
	got, _ := n.MarshalJSON()
	want := `{"id":"x","kinds":["AWS_User"],"properties":{"z":1,"a":2,"m":3}}`
	if string(got) != want {
		t.Fatalf("insertion order not preserved:\n got=%s\nwant=%s", got, want)
	}
}

func TestEdgeWireShapeWithProps(t *testing.T) {
	e := NewEdge("a", "b", KindContains).Set("is_traversable", true)
	got, _ := e.MarshalJSON()
	want := `{"kind":"AWS_Contains","start":{"value":"a","match_by":"id"},"end":{"value":"b","match_by":"id"},"properties":{"is_traversable":true}}`
	if string(got) != want {
		t.Fatalf("edge mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestEdgeOmitsEmptyProperties(t *testing.T) {
	e := NewEdge("a", "b", KindMemberOf)
	got, _ := e.MarshalJSON()
	want := `{"kind":"AWS_MemberOf","start":{"value":"a","match_by":"id"},"end":{"value":"b","match_by":"id"}}`
	if string(got) != want {
		t.Fatalf("empty edge properties should be omitted:\n got=%s\nwant=%s", got, want)
	}
}

func TestEncodeID(t *testing.T) {
	// The exact example the integration validator produces (agent-confirmed).
	got := EncodeID("arn:aws:iam::813246817415:role/inttest-WildcardCITrustRole")
	want := "arn_aws_iam__813246817415_role/inttest-WildcardCITrustRole"
	if got != want {
		t.Fatalf("got=%s want=%s", got, want)
	}
	if EncodeID("*") != "*" {
		t.Fatalf("wildcard principal id must pass through unchanged")
	}
}

func TestSchemaKindCounts(t *testing.T) {
	if len(AllNodeKinds) != 20 {
		t.Fatalf("expected 20 node kinds, got %d", len(AllNodeKinds))
	}
	if len(AllEdgeKinds) != 156 {
		t.Fatalf("expected 156 edge kinds, got %d", len(AllEdgeKinds))
	}
}

func TestTraversableFlag(t *testing.T) {
	if !KindContains.IsTraversable() {
		t.Fatal("AWS_Contains should be traversable")
	}
	if KindMemberOf.IsTraversable() {
		t.Fatal("AWS_MemberOf should not be traversable")
	}
}
