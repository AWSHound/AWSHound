// Package runtime orchestrates the collect→ingest→build→emit pipeline. Unlike
// AWSHound's multiprocess builder, graph construction is a single in-process
// pass over the shared store; goroutine parallelism can be layered on per phase
// without any cross-process state sharing.
package runtime

import (
	"io"
	"strings"

	"github.com/AWSHound/AWSHound/internal/build"
	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// StreamBuildToBuilt builds the graph and writes the built.json artifact to w
// while bounding node memory: nodes are streamed straight to w through
// build.StreamNodes (the volume-scaling node set never accumulates), then edges
// are appended. The bytes are identical to BuildGraph + graph.WriteBuilt. Returns
// the node and edge counts. A nil p disables progress reporting.
// EdgeFamilyTimer receives a per-edge-family wall-clock timing (the --metrics
// per-processor breakdown). *metrics.RunMetrics satisfies it; a nil value disables
// the breakdown.
type EdgeFamilyTimer interface {
	RecordEdgeFamily(name string, millis int64)
}

func StreamBuildToBuilt(s *store.Store, w io.Writer, p BuildProgress, timer EdgeFamilyTimer) (int, int, error) {
	stage := func(name string, total int) {
		if p != nil {
			p.Stage(name, total)
		}
	}
	advance := func(n int) {
		if p != nil {
			p.Advance(n)
		}
	}
	detail := func(format string, args ...any) {
		if detailer, ok := p.(interface{ Detail(string, ...any) }); ok {
			detailer.Detail(format, args...)
		}
	}
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		return 0, 0, err
	}

	sw := graph.NewBuiltStreamWriter(w)

	stage("Build nodes", len(s.Accounts()))
	nodeCount := 0
	build.StreamNodes(s, func(n *graph.Node) {
		detail("building %s node %s", primaryNodeKind(n), n.ID)
		// StreamNodes emits each node id exactly once, in its merged form, so this
		// is the post-merge emit point the id fallback requires (see
		// build.ApplyAccountNameFallback).
		build.ApplyAccountNameFallback(n)
		_ = sw.Node(n)
		nodeCount++
	}, func() { advance(1) })
	if err := sw.Edges(); err != nil {
		return 0, 0, err
	}

	stage("Build edges", edges.NumFamilies())
	edgeCount := 0
	var edgeErr error
	var familyDone func(string, int64)
	if timer != nil {
		familyDone = timer.RecordEdgeFamily
	}
	edges.StreamEdges(s, pe, edges.EdgeProgress{
		Advance: func() { advance(1) },
		FamilyStart: func(name string) {
			if labeler, ok := p.(interface{ SetStageLabel(string) }); ok {
				labeler.SetStageLabel("Building " + name + " edges")
			}
			detail("building %s edge family", name)
		},
		FamilyDone: familyDone,
	}, func(e *graph.Edge) {
		if edgeErr != nil {
			return
		}
		detail("building %s edge %s -> %s", e.Kind, e.Start, e.End)
		if err := sw.Edge(e); err != nil {
			edgeErr = err
			return
		}
		edgeCount++
	})
	if labeler, ok := p.(interface{ SetStageLabel(string) }); ok {
		labeler.SetStageLabel("Build edges")
	}
	if edgeErr != nil {
		return 0, 0, edgeErr
	}
	if err := sw.Close(); err != nil {
		return 0, 0, err
	}
	return nodeCount, edgeCount, nil
}

// BuildProgress receives stage/advance signals from BuildGraphWithProgress so a
// caller can drive a progress display through the build. It is satisfied by
// *progress.Tracker (and progress.Reporter); a nil BuildProgress disables
// reporting. Edge progress advances once per completed family; an optional
// SetStageLabel(string) method lets a display name the family currently running
// without resetting the counter.
type BuildProgress interface {
	Stage(name string, total int)
	Advance(n int)
}

// BuildGraph turns a populated store into the OpenGraph node and edge sets:
// it constructs the policy evaluator, runs every node parser (merging same-id
// nodes across accounts), and runs every edge family (deduped).
func BuildGraph(s *store.Store) ([]*graph.Node, []*graph.Edge, error) {
	return BuildGraphWithProgress(s, nil)
}

// BuildGraphWithProgress is BuildGraph instrumented for progress: it reports a
// "Build nodes" stage advancing per account and a "Build edges" stage advancing
// per edge family. A nil p makes it behave exactly like BuildGraph.
func BuildGraphWithProgress(s *store.Store, p BuildProgress) ([]*graph.Node, []*graph.Edge, error) {
	stage := func(name string, total int) {
		if p != nil {
			p.Stage(name, total)
		}
	}
	advance := func(n int) {
		if p != nil {
			p.Advance(n)
		}
	}
	detail := func(format string, args ...any) {
		if detailer, ok := p.(interface{ Detail(string, ...any) }); ok {
			detailer.Detail(format, args...)
		}
	}
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		return nil, nil, err
	}

	accounts := s.Accounts()
	stage("Build nodes", len(accounts))
	var nodes []*graph.Node
	for _, acct := range accounts {
		detail("building nodes for account %s", acct.ID)
		nodes = append(nodes, build.AccountNodes(acct)...)
		advance(1)
	}
	nodes = build.MergeNodes(nodes)
	// Post-merge, so an account's id fallback can never clobber a real name
	// supplied by another account's org data (see build.setAccountName).
	for _, n := range nodes {
		build.ApplyAccountNameFallback(n)
	}

	stage("Build edges", edges.NumFamilies())
	es := edges.AllEdgesProgress(s, pe, edges.EdgeProgress{
		Advance: func() { advance(1) },
		FamilyStart: func(name string) {
			if labeler, ok := p.(interface{ SetStageLabel(string) }); ok {
				labeler.SetStageLabel("Building " + name + " edges")
			}
			detail("building %s edge family", name)
		},
	})
	if labeler, ok := p.(interface{ SetStageLabel(string) }); ok {
		labeler.SetStageLabel("Build edges")
	}
	return nodes, es, nil
}

func primaryNodeKind(n *graph.Node) string {
	if len(n.Kinds) == 0 {
		return "unknown"
	}
	return string(n.Kinds[0])
}

// AccountIDFromGAAD derives the account id from the first principal ARN in a
// GAAD response (arn:aws:iam::<account>:...). Returns "" if none is found.
func AccountIDFromGAAD(g *model.AuthDetails) string {
	first := func() string {
		switch {
		case len(g.UserDetailList) > 0:
			return g.UserDetailList[0].Arn
		case len(g.RoleDetailList) > 0:
			return g.RoleDetailList[0].Arn
		case len(g.GroupDetailList) > 0:
			return g.GroupDetailList[0].Arn
		case len(g.Policies) > 0:
			return g.Policies[0].Arn
		}
		return ""
	}()
	parts := strings.Split(first, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
