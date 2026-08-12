package ingest_test

import (
	"os"
	"runtime/pprof"
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/ingest"
	"github.com/AWSHound/AWSHound/internal/store"
)

type profNoop struct{}

func (profNoop) Stage(string, int) {}
func (profNoop) AddTotal(int)      {}
func (profNoop) Advance(int)       {}
func (profNoop) Log(string)        {}
func (profNoop) Stop()             {}

// TestProfileEdgeBuild ingests the raw account dir in GOAWS_PROF_DIR and CPU-profiles
// just the edge build to GOAWS_PROF_OUT. GOAWS_PROF_FAMILY=s3 selects the bounded
// production S3 stream; otherwise it profiles the compatibility AllEdges path.
// Skipped unless both required env vars are set, so it never runs in the normal
// suite. Analyze with:
//
//	go tool pprof -top -nodecount=40 <GOAWS_PROF_OUT>
func TestProfileEdgeBuild(t *testing.T) {
	dir := os.Getenv("GOAWS_PROF_DIR")
	out := os.Getenv("GOAWS_PROF_OUT")
	if dir == "" || out == "" {
		t.Skip("set GOAWS_PROF_DIR and GOAWS_PROF_OUT to profile")
	}

	s := store.New()
	if _, err := ingest.Directory(s, dir, profNoop{}, nil); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pprof.StartCPUProfile(f); err != nil {
		t.Fatal(err)
	}
	count := 0
	if os.Getenv("GOAWS_PROF_FAMILY") == "s3" {
		edges.StreamS3Edges(s, pe, func(*graph.Edge) { count++ })
	} else {
		count = len(edges.AllEdges(s, pe))
	}
	pprof.StopCPUProfile()
	t.Logf("built %d edges from %s", count, dir)
}
