package runtime_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/emit"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/runtime"
	"github.com/AWSHound/AWSHound/internal/store"
)

// End-to-end: the streaming CLI path (StreamBuildToBuilt -> StreamGraphFromBuilt)
// must produce a graph.json byte-identical to the accumulate path
// (BuildGraph -> emit.WriteGraph). This is the whole-pipeline §9 gate.
func TestStreamingPipelineMatchesAccumulateGraph(t *testing.T) {
	s := newMultiAccountStore(t)

	// Accumulate path -> graph.json.
	nodes, edges, err := runtime.BuildGraph(s)
	if err != nil {
		t.Fatal(err)
	}
	var refGraph bytes.Buffer
	if err := emit.WriteGraph(&refGraph, nodes, edges); err != nil {
		t.Fatal(err)
	}

	// Streaming path -> built.json -> graph.json (what `all` does).
	var built bytes.Buffer
	if _, _, err := runtime.StreamBuildToBuilt(s, &built, nil, nil); err != nil {
		t.Fatal(err)
	}
	var gotGraph bytes.Buffer
	if err := emit.StreamGraphFromBuilt(bytes.NewReader(built.Bytes()), &gotGraph); err != nil {
		t.Fatal(err)
	}

	if gotGraph.String() != refGraph.String() {
		t.Fatalf("streaming pipeline graph.json differs from accumulate path")
	}
}

func TestStreamingPipelineNamesCurrentFamilyAndRestoresCompletedStage(t *testing.T) {
	s := newMultiAccountStore(t)
	path := filepath.Join(t.TempDir(), "progress.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })

	reporter := progress.Multi(progress.New(f))
	var built bytes.Buffer
	if _, _, err := runtime.StreamBuildToBuilt(s, &built, reporter, nil); err != nil {
		t.Fatal(err)
	}
	reporter.Stop()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	completed := fmt.Sprintf("(%d/%d)", edges.NumFamilies(), edges.NumFamilies())
	if !strings.Contains(got, "Building iam_manipulation edges") {
		t.Errorf("progress output did not name the current edge family; got:\n%s", got)
	}
	if !strings.Contains(got, "Build edges") || !strings.Contains(got, completed) {
		t.Errorf("progress did not restore the completed Build edges label; got:\n%s", got)
	}
}

func TestStreamingPipelineReportsVerboseBuildDetails(t *testing.T) {
	s := newMultiAccountStore(t)
	path := filepath.Join(t.TempDir(), "verbose.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })

	reporter := progress.Multi(progress.NewLogger(f))
	var built bytes.Buffer
	if _, _, err := runtime.StreamBuildToBuilt(s, &built, reporter, nil); err != nil {
		t.Fatal(err)
	}
	reporter.Stop()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{
		"building AWS_User node arn:aws:iam::111111111111:user/u",
		"building structural edge family",
		"building AWS_Contains edge",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("verbose build output missing %q; got:\n%s", want, got)
		}
	}
}

// newMultiAccountStore builds a two-account store exercising IAM, a shared
// AWS-managed policy (last-wins merge), and S3 objects (streamed node tier).
func newMultiAccountStore(t *testing.T) *store.Store {
	t.Helper()
	s := store.New()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	for i, acct := range []string{"111111111111", "222222222222"} {
		s.AddAuthDetails(acct, &model.AuthDetails{
			UserDetailList: []model.UserDetail{{Arn: "arn:aws:iam::" + acct + ":user/u", UserName: "u",
				UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
			Policies: []model.PolicyDetail{{Arn: "arn:aws:iam::aws:policy/ReadOnlyAccess", PolicyName: "ReadOnlyAccess", AttachmentCount: i + 1}},
		})
		store.IngestS3(s, acct, &model.S3Data{
			Buckets: []model.S3Bucket{{Name: "b-" + acct, Arn: "arn:aws:s3:::b-" + acct,
				Objects: []model.S3Object{{Key: "k1"}, {Key: "k2"}}}},
		})
	}
	return s
}

// StreamBuildToBuilt must write a built.json byte-identical to the
// accumulate-then-WriteBuilt path (BuildGraph + graph.WriteBuilt), while bounding
// node memory. This is the §9 streaming build's correctness gate.
func TestStreamBuildToBuiltMatchesAccumulate(t *testing.T) {
	s := store.New()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	s.AddAuthDetails("111111111111", &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: "arn:aws:iam::111111111111:user/a", UserName: "a",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
		Policies: []model.PolicyDetail{{Arn: "arn:aws:iam::aws:policy/ReadOnlyAccess", PolicyName: "ReadOnlyAccess", AttachmentCount: 3}},
	})
	store.IngestS3(s, "111111111111", &model.S3Data{
		Buckets: []model.S3Bucket{{Name: "b", Arn: "arn:aws:s3:::b", Objects: []model.S3Object{{Key: "k"}}}},
	})

	// Reference: accumulate then WriteBuilt.
	nodes, edges, err := runtime.BuildGraph(s)
	if err != nil {
		t.Fatal(err)
	}
	var ref bytes.Buffer
	if err := graph.WriteBuilt(&ref, nodes, edges); err != nil {
		t.Fatal(err)
	}

	// Streaming path.
	var got bytes.Buffer
	nc, ec, err := runtime.StreamBuildToBuilt(s, &got, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != ref.String() {
		t.Fatalf("streamed built differs from accumulate path:\n stream: %s\n ref:    %s", got.String(), ref.String())
	}
	if nc != len(nodes) || ec != len(edges) {
		t.Fatalf("counts (%d,%d) != (%d,%d)", nc, ec, len(nodes), len(edges))
	}
}
