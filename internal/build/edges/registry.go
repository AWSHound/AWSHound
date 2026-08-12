// Package edges holds the graph edge processors (structural relationships and
// attack paths), ported from AWSHound's core/graph/edges/. Each family exposes a
// <Family>Edges(store, evaluator) entry point; AllEdges runs them all.
package edges

import (
	"time"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// edgeFamily is one edge processor plus optional finer-grained progress. build
// produces the family's edges, calling onItem once per inner work unit it opts to
// report; innerUnits, when non-nil, returns how many onItem calls build will make
// for store s, so the registry can grow the progress denominator before build
// runs. A family with no sub-progress leaves innerUnits nil and ignores onItem —
// it then contributes only its single per-family tick, exactly as before. Every
// unit added via innerUnits MUST be matched by an onItem call so the stage still
// finishes at 100%.
type edgeFamily struct {
	name  string
	build func(s *store.Store, pe *eval.PolicyEvaluator, onItem func()) []*graph.Edge
	// stream, when non-nil, is the bounded production path. build remains the
	// accumulating compatibility path used by AllEdges and direct tests.
	stream     func(s *store.Store, pe *eval.PolicyEvaluator, onItem func(), emit func(*graph.Edge))
	innerUnits func(s *store.Store) int
	// disjointStream guarantees that stream emits unique (start,end,kind) keys
	// whose kinds no other registered family owns. Such a family can bypass the
	// org-wide seen map; retaining one key per S3 object edge would merely replace
	// the eliminated edge slice with another O(graph-size) memory ceiling.
	disjointStream bool
}

// plain adapts a bare edge-family entry point (no sub-progress) to an edgeFamily.
func plain(name string, fn func(*store.Store, *eval.PolicyEvaluator) []*graph.Edge) edgeFamily {
	return edgeFamily{name: name, build: func(s *store.Store, pe *eval.PolicyEvaluator, _ func()) []*graph.Edge {
		return fn(s, pe)
	}}
}

// families is every edge-family entry point, in execution order. IAM manipulation
// reports per-account work and S3 reports per-principal work; both otherwise look
// stalled for long high-cardinality scans. The rest tick once when they finish.
var families = []edgeFamily{
	plain("structural", StructuralEdges),
	{name: "iam_manipulation", build: iamManipulationEdges, innerUnits: iamManipulationUnits},
	plain("role_trust", RoleTrustEdges),
	plain("credential", CredentialEdges),
	{
		name: "s3",
		build: func(s *store.Store, pe *eval.PolicyEvaluator, onPrincipal func()) []*graph.Edge {
			var out []*graph.Edge
			StreamS3EdgesProgress(s, pe, onPrincipal, func(e *graph.Edge) { out = append(out, e) })
			return out
		},
		stream: func(s *store.Store, pe *eval.PolicyEvaluator, onPrincipal func(), emit func(*graph.Edge)) {
			StreamS3EdgesProgress(s, pe, onPrincipal, emit)
		},
		innerUnits:     s3StreamUnits,
		disjointStream: true,
	},
	plain("kms", KMSEdges),
	plain("ssm", SSMEdges),
	plain("lambda", LambdaEdges),
	plain("cloudformation", CloudFormationEdges),
	plain("ec2", EC2Edges),
	plain("eks", EKSEdges),
}

func s3StreamUnits(s *store.Store) int {
	units := 0
	for _, account := range s.Accounts() {
		units += len(principalARNs(account))
	}
	return units
}

// NumFamilies reports how many edge families AllEdges runs, so a caller can size
// a progress total before iterating. It is the initial denominator; a family may
// grow it at runtime via its innerUnits (see EdgeProgress and edgeFamily).
func NumFamilies() int { return len(families) }

// EdgeProgress drives the Build edges stage. AddTotal grows the denominator by a
// family's discovered inner-unit count (see edgeFamily.innerUnits); Advance ticks
// one completed unit — one per finished family, plus one per inner item for a
// family that reports sub-progress. Either callback may be nil (the zero
// EdgeProgress disables reporting entirely), so use the addTotal/advance helpers.
type EdgeProgress struct {
	AddTotal func(int)
	Advance  func()
	// FamilyStart, when set, is called before an edge family begins.
	FamilyStart func(name string)
	// FamilyDone, when set, is called once per edge family with its name and
	// wall-clock duration — the per-processor breakdown the --metrics report shows
	// (the Go counterpart of AWSHound's wave_edge:<Processor> timings).
	FamilyDone func(name string, millis int64)
}

func (p EdgeProgress) addTotal(n int) {
	if p.AddTotal != nil {
		p.AddTotal(n)
	}
}

func (p EdgeProgress) advance() {
	if p.Advance != nil {
		p.Advance()
	}
}

func (p EdgeProgress) familyStart(name string) {
	if p.FamilyStart != nil {
		p.FamilyStart(name)
	}
}

// AllEdges runs every edge family over the store and returns the deduped result.
// Dedup is on (start, end, kind): the same logical edge can be produced by more
// than one processor (e.g. an SSM attack path firing via two policy statements),
// which AWSHound also collapses at write time.
func AllEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	return AllEdgesProgress(s, pe, EdgeProgress{})
}

// AllEdgesProgress is AllEdges instrumented for progress (see EdgeProgress): it
// grows the denominator by each family's inner-unit count before running it and
// advances once per inner item and once per finished family. A zero EdgeProgress
// behaves exactly like AllEdges.
func AllEdgesProgress(s *store.Store, pe *eval.PolicyEvaluator, prog EdgeProgress) []*graph.Edge {
	var all []*graph.Edge
	for _, family := range families {
		prog.familyStart(family.name)
		all = append(all, family.build(s, pe, familyOnItem(family, s, prog))...)
		prog.advance()
	}
	return DedupEdges(all)
}

// familyOnItem grows the progress denominator by family's inner-unit count (if it
// reports one) and returns the per-item tick to hand to family.build. A family
// with no sub-progress gets a no-op onItem and leaves the denominator untouched,
// so it still contributes only its single per-family Advance.
func familyOnItem(family edgeFamily, s *store.Store, prog EdgeProgress) func() {
	if family.innerUnits == nil || prog.AddTotal == nil || prog.Advance == nil {
		return func() {}
	}
	if n := family.innerUnits(s); n > 0 {
		prog.addTotal(n)
		return prog.advance
	}
	return func() {}
}

// StreamEdges emits every family's edges through emit, deduped by (start, end,
// kind) keeping the first occurrence — the same sequence AllEdges returns, but
// without materializing the whole edge slice. Ordinary families retain a dedup
// key across families. A streaming family whose key-space is declared disjoint
// (currently S3) emits directly, so its volume does not grow that key set either.
// prog, if set, drives the progress display: per inner item and per completed
// family (see EdgeProgress).
func StreamEdges(s *store.Store, pe *eval.PolicyEvaluator, prog EdgeProgress, emit func(*graph.Edge)) {
	seen := make(map[[3]string]struct{})
	emitDedup := func(e *graph.Edge) {
		key := [3]string{e.Start, e.End, string(e.Kind)}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		emit(e)
	}
	for _, family := range families {
		prog.familyStart(family.name)
		start := time.Now()
		onItem := familyOnItem(family, s, prog)
		if family.stream != nil {
			familyEmit := emitDedup
			if family.disjointStream {
				familyEmit = emit
			}
			family.stream(s, pe, onItem, familyEmit)
		} else {
			for _, e := range family.build(s, pe, onItem) {
				emitDedup(e)
			}
		}
		if prog.FamilyDone != nil {
			prog.FamilyDone(family.name, time.Since(start).Milliseconds())
		}
		prog.advance()
	}
}

// DedupEdges removes duplicate (start, end, kind) triples, keeping the first.
func DedupEdges(edges []*graph.Edge) []*graph.Edge {
	seen := make(map[[3]string]struct{}, len(edges))
	out := edges[:0]
	for _, e := range edges {
		key := [3]string{e.Start, e.End, string(e.Kind)}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}
