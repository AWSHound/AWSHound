package build_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/build"
	"github.com/AWSHound/AWSHound/internal/emit"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// TestIAMSliceEndToEndOffline drives the real collect→store→node→emit path with
// no AWS: it feeds AWSHound's GAAD fixture through ingest, the IAM node parser,
// the assembler, and the emitter, then validates the OpenGraph output.
func TestIAMSliceEndToEndOffline(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/sample_auth_details.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err = model.NormalizeGAADDocs(raw)
	if err != nil {
		t.Fatal(err)
	}
	var gaad model.AuthDetails
	if err := json.Unmarshal(raw, &gaad); err != nil {
		t.Fatalf("fixture did not unmarshal into model.AuthDetails: %v", err)
	}

	s := store.New()
	s.AddAuthDetails("123456789012", &gaad)
	acct := s.Account("123456789012")

	nodes := build.AccountNodes(acct)
	if len(nodes) == 0 {
		t.Fatal("no nodes emitted from the GAAD fixture")
	}

	var buf bytes.Buffer
	if err := emit.WriteGraph(&buf, nodes, nil); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Graph struct {
			Nodes []struct {
				ID         string         `json:"id"`
				Kinds      []string       `json:"kinds"`
				Properties map[string]any `json:"properties"`
			} `json:"nodes"`
		} `json:"graph"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("emitted artifact is not valid JSON: %v", err)
	}
	if doc.Metadata["source_kind"] != "AWS" {
		t.Fatalf("metadata.source_kind = %v", doc.Metadata["source_kind"])
	}

	kinds := map[string]int{}
	for _, n := range doc.Graph.Nodes {
		for _, k := range n.Kinds {
			kinds[k]++
		}
		if strings.Contains(n.ID, ":") {
			t.Errorf("node id not colon-encoded: %s", n.ID)
		}
		if _, ok := n.Properties["arn"]; !ok {
			t.Errorf("node %s missing 'arn' property", n.ID)
		}
	}
	// The fixture has one user, one group, one role, one managed policy.
	for _, want := range []string{"AWS_User", "AWS_Group", "AWS_Role", "AWS_Policy"} {
		if kinds[want] == 0 {
			t.Errorf("expected >=1 %s node; got kinds=%v", want, kinds)
		}
	}
	t.Logf("emitted %d node(s): %v", len(doc.Graph.Nodes), kinds)
}
