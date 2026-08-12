// This file ports the six S3 meta-edge processors (core/graph/edges/meta/, the
// S3ObjectAll/Write/Read and S3BucketAll/Write/Read entries) together with the
// wave-aware suppression the runtime framework (runtime/dag.py +
// runtime/edge_store.py) applies around them.
//
// Each meta edge fires at a (start, end) pair only when EVERY one of its
// constituent kinds is present at that pair, and its properties aggregate the
// constituents' allow_sources (deduplicated, order-preserving) and conditions
// (concatenated) exactly as MetaEdgeBaseProcessor._build_meta_edge does. When a
// meta fires it SUPPRESSES its constituents at that pair — they are removed from
// the surviving edge set in favour of the meta.
//
// Wave order is the crux. The DAG topo-sort places the two ALL metas in one wave,
// the two WRITE metas in the next, the two READ metas last (each lower-priority
// meta consumes its family's higher meta kind via priority_predecessors). Crucially
// suppression is applied AFTER a whole wave completes, so both ALL metas read the
// full, unsuppressed constituent set before either suppresses — then WRITE reads
// the post-ALL state, and READ the post-WRITE state. This is why CanPutObject
// (shared by the bucket AND object families) couples them: in the no-objects
// fallback, where object-family edges land on the bucket node, a bucket-ALL that
// fires and deletes CanPutObject can starve a same-pair object-WRITE in the next
// wave. The simulation below reproduces that faithfully by computing every meta in
// a wave against the pre-wave state, then applying all of the wave's suppressions.
package edges

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/graph"
)

// s3Pair is a directed (start, end) endpoint pair used to group constituents.
type s3Pair struct {
	start string
	end   string
}

// s3MetaSpec binds a meta edge kind to its is_traversable flag and its ordered
// constituent kinds. constituents doubles as the suppresses set (deleted at every
// pair where the meta fires), matching MetaEdgeBaseProcessor where suppresses ==
// constituents.
type s3MetaSpec struct {
	kind         graph.EdgeKind
	traversable  bool
	constituents []graph.EdgeKind
}

// The six S3 meta specs. Only S3BucketAll is traversable (see the meta __init__
// bindings and graph.kinds' traversable set); the other five carry
// is_traversable=false explicitly, as MetaEdgeBaseProcessor always sets it.
var (
	s3ObjectAll = s3MetaSpec{
		kind: graph.KindS3ObjectAll,
		constituents: []graph.EdgeKind{
			graph.KindCanGetObject,
			graph.KindCanGetObjectACL,
			graph.KindCanPutObject,
			graph.KindCanDeleteObject,
			graph.KindCanPutObjectACL,
		},
	}
	s3ObjectWrite = s3MetaSpec{
		kind: graph.KindS3ObjectWrite,
		constituents: []graph.EdgeKind{
			graph.KindCanGetObject,
			graph.KindCanGetObjectACL,
			graph.KindCanPutObject,
		},
	}
	s3ObjectRead = s3MetaSpec{
		kind: graph.KindS3ObjectRead,
		constituents: []graph.EdgeKind{
			graph.KindCanGetObject,
			graph.KindCanGetObjectACL,
		},
	}
	s3BucketAll = s3MetaSpec{
		kind:        graph.KindS3BucketAll,
		traversable: true,
		constituents: []graph.EdgeKind{
			graph.KindCanListBucket,
			graph.KindCanGetBucketACL,
			graph.KindCanGetBucketPolicy,
			graph.KindCanPutObject,
			graph.KindCanDeleteBucket,
			graph.KindCanDeleteBucketPolicy,
			graph.KindCanPutBucketACL,
			graph.KindCanPutBucketPolicy,
			graph.KindCanPutBucketPublicAccessBlock,
			graph.KindCanPutBucketOwnershipControls,
		},
	}
	s3BucketWrite = s3MetaSpec{
		kind: graph.KindS3BucketWrite,
		constituents: []graph.EdgeKind{
			graph.KindCanListBucket,
			graph.KindCanGetBucketACL,
			graph.KindCanGetBucketPolicy,
			graph.KindCanPutObject,
		},
	}
	s3BucketRead = s3MetaSpec{
		kind: graph.KindS3BucketRead,
		constituents: []graph.EdgeKind{
			graph.KindCanListBucket,
			graph.KindCanGetBucketACL,
			graph.KindCanGetBucketPolicy,
		},
	}
)

// s3MetaWaves is the DAG wave assignment: ALL, then WRITE, then READ, with the
// object and bucket cascades locked in step. Suppression runs at the end of each
// wave (see s3ApplyMetaWaves), so every meta in a wave reads the same pre-wave
// constituent state.
var s3MetaWaves = [][]s3MetaSpec{
	{s3ObjectAll, s3BucketAll},
	{s3ObjectWrite, s3BucketWrite},
	{s3ObjectRead, s3BucketRead},
}

// s3ApplyMetaWaves consolidates the constituent edges into the S3 meta edges and
// returns the final edge set: every meta edge that fired, plus every constituent
// that survived suppression. Constituents that no meta consumes (the account-level
// ListAllMyBuckets / PutAccountPublicAccessBlock edges, and any partial bundle)
// pass through unchanged.
func s3ApplyMetaWaves(constituents []*graph.Edge) []*graph.Edge {
	// Group constituents by endpoint pair. (start, end, kind) is unique across the
	// constituent set, so a plain kind->edge map per pair loses nothing.
	byPair := make(map[s3Pair]map[graph.EdgeKind]*graph.Edge)
	var pairOrder []s3Pair
	for _, e := range constituents {
		pk := s3Pair{start: e.Start, end: e.End}
		m := byPair[pk]
		if m == nil {
			m = make(map[graph.EdgeKind]*graph.Edge)
			byPair[pk] = m
			pairOrder = append(pairOrder, pk)
		}
		m[e.Kind] = e
	}
	sort.Slice(pairOrder, func(i, j int) bool {
		if pairOrder[i].start != pairOrder[j].start {
			return pairOrder[i].start < pairOrder[j].start
		}
		return pairOrder[i].end < pairOrder[j].end
	})

	out := make([]*graph.Edge, 0, len(constituents))
	for _, pk := range pairOrder {
		out = append(out, s3ApplyMetaPair(byPair[pk])...)
	}
	return out
}

// s3ApplyMetaPair is the bounded form of s3ApplyMetaWaves: all S3 meta
// predicates and suppressions depend only on the kinds present at one directed
// endpoint pair, so the three waves can be completed and released independently.
// The returned kinds are sorted, making a caller that walks pairs in
// (start,end) order byte-identical to S3Edges' historical final sort.
func s3ApplyMetaPair(edges map[graph.EdgeKind]*graph.Edge) []*graph.Edge {
	if len(edges) == 0 {
		return nil
	}
	var pk s3Pair
	for _, e := range edges {
		pk = s3Pair{start: e.Start, end: e.End}
		break
	}

	var out []*graph.Edge
	for _, wave := range s3MetaWaves {
		// Every spec in a wave reads the same pre-suppression state.
		var fired []s3MetaSpec
		for _, spec := range wave {
			if !allPresent(edges, spec.constituents) {
				continue
			}
			out = append(out, s3BuildMetaEdge(pk, spec, edges))
			fired = append(fired, spec)
		}
		// Suppress only after the whole wave has fired.
		for _, spec := range fired {
			for _, kind := range spec.constituents {
				delete(edges, kind)
			}
		}
	}
	for _, e := range edges {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Kind) < string(out[j].Kind) })
	return out
}

// s3BuildMetaEdge constructs one meta edge, aggregating allow_sources
// (deduplicated, first-seen order) and conditions (concatenated) across the
// present constituents in the spec's declared order — a byte-for-byte port of
// MetaEdgeBaseProcessor._build_meta_edge. Property insertion order is
// is_traversable, allow_sources, conditions.
func s3BuildMetaEdge(pk s3Pair, spec s3MetaSpec, m map[graph.EdgeKind]*graph.Edge) *graph.Edge {
	var allSources []string
	seen := make(map[string]bool)
	var allConds []map[string]any

	for _, k := range spec.constituents {
		e := m[k]
		if e == nil {
			continue
		}
		if s, ok := e.Props.Get("allow_sources").(string); ok && s != "" {
			for _, src := range strings.Split(s, ", ") {
				if src != "" && !seen[src] {
					seen[src] = true
					allSources = append(allSources, src)
				}
			}
		}
		if c, ok := e.Props.Get("conditions").(string); ok && c != "" {
			var decoded []map[string]any
			if json.Unmarshal([]byte(c), &decoded) == nil && len(decoded) > 0 {
				allConds = append(allConds, decoded...)
			}
		}
	}

	e := graph.NewEdge(pk.start, pk.end, spec.kind)
	e.Set("is_traversable", spec.traversable)
	e.Set("allow_sources", strings.Join(allSources, ", "))
	e.Set("conditions", conditionsJSON(allConds))
	return e
}
