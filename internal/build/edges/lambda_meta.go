// This file ports the two Lambda meta-edge processors (core/graph/edges/meta/, the
// LambdaFunctionAll and LambdaFunctionWrite entries) together with the wave-aware
// suppression the runtime framework (runtime/dag.py + runtime/edge_store.py) applies
// around them.
//
// Each meta edge fires at a (start, end) pair only when EVERY one of its constituent
// kinds is present at that pair, and its properties aggregate the constituents'
// allow_sources (deduplicated, order-preserving) and conditions (concatenated)
// exactly as MetaEdgeBaseProcessor._build_meta_edge does. When a meta fires it
// SUPPRESSES its constituents at that pair — they are removed from the surviving edge
// set in favour of the meta.
//
// Wave order. LambdaFunctionWrite lists LambdaFunctionAll as a priority_predecessor,
// so the DAG topo-sort runs LambdaFunctionAll first (wave 1) and LambdaFunctionWrite
// second (wave 2). Suppression is applied AFTER a whole wave completes, so
// LambdaFunctionAll reads the full constituent set before it suppresses, then
// LambdaFunctionWrite reads the post-All state: at any (principal, function) pair
// where All fired (all eight constituents present), Invoke/UpdateCode/
// UpdateConfiguration are already gone, so Write finds nothing and skips. Where All
// did not fire but those three are present, Write fires and consolidates them.
//
// Both Lambda metas carry is_traversable=true (their Python bindings set
// is_traversable=True). The function-scoped constituents that are NOT part of either
// meta at a given pair (e.g. a lone cross-account Invoke edge, or a partial
// capability set) pass through unchanged; the account-scoped AWS_CanCreateLambda
// Function primitive is never a constituent and always passes through.
package edges

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/graph"
)

// lambdaPair is a directed (start, end) endpoint pair used to group constituents.
type lambdaPair struct {
	start string
	end   string
}

// lambdaMetaSpec binds a meta edge kind to its is_traversable flag and its ordered
// constituent kinds. constituents doubles as the suppresses set (deleted at every
// pair where the meta fires), matching MetaEdgeBaseProcessor where suppresses ==
// constituents.
type lambdaMetaSpec struct {
	kind         graph.EdgeKind
	traversable  bool
	constituents []graph.EdgeKind
}

// The two Lambda meta specs. Constituent order follows the Python frozenset literal
// (it only affects allow_sources/conditions aggregation order, matching the legacy
// consolidator's declared order).
var (
	lambdaFunctionAll = lambdaMetaSpec{
		kind:        graph.KindLambdaFunctionAll,
		traversable: true,
		constituents: []graph.EdgeKind{
			graph.KindCanInvokeLambdaFunction,
			graph.KindCanUpdateLambdaCode,
			graph.KindCanUpdateLambdaConfiguration,
			graph.KindCanUpdateLambdaURLConfig,
			graph.KindCanAddLambdaPermission,
			graph.KindCanRemoveLambdaPermission,
			graph.KindCanCreateLambdaEventSource,
			graph.KindCanDeleteLambdaFunction,
		},
	}
	lambdaFunctionWrite = lambdaMetaSpec{
		kind:        graph.KindLambdaFunctionWrite,
		traversable: true,
		constituents: []graph.EdgeKind{
			graph.KindCanInvokeLambdaFunction,
			graph.KindCanUpdateLambdaCode,
			graph.KindCanUpdateLambdaConfiguration,
		},
	}
)

// lambdaMetaWaves is the DAG wave assignment: ALL, then WRITE. Suppression runs at
// the end of each wave (see lambdaApplyMetaWaves), so every meta in a wave reads the
// same pre-wave constituent state.
var lambdaMetaWaves = [][]lambdaMetaSpec{
	{lambdaFunctionAll},
	{lambdaFunctionWrite},
}

// lambdaApplyMetaWaves consolidates the constituent edges into the Lambda meta edges
// and returns the final edge set: every meta edge that fired, plus every constituent
// that survived suppression. Constituents no meta consumes (a lone cross-account
// Invoke edge, a partial capability set, the account-level CanCreateLambdaFunction
// edges) pass through unchanged.
func lambdaApplyMetaWaves(constituents []*graph.Edge) []*graph.Edge {
	// Group constituents by endpoint pair. (start, end, kind) is unique across the
	// constituent set, so a plain kind->edge map per pair loses nothing.
	byPair := make(map[lambdaPair]map[graph.EdgeKind]*graph.Edge)
	var pairOrder []lambdaPair
	for _, e := range constituents {
		pk := lambdaPair{start: e.Start, end: e.End}
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

	var metaEdges []*graph.Edge
	for _, wave := range lambdaMetaWaves {
		// Phase 1: fire every meta in the wave against the pre-wave state.
		type lambdaFired struct {
			spec lambdaMetaSpec
			pk   lambdaPair
		}
		var fired []lambdaFired
		for _, spec := range wave {
			for _, pk := range pairOrder {
				m := byPair[pk]
				if m == nil || !allPresent(m, spec.constituents) {
					continue
				}
				metaEdges = append(metaEdges, lambdaBuildMetaEdge(pk, spec, m))
				fired = append(fired, lambdaFired{spec: spec, pk: pk})
			}
		}
		// Phase 2: suppress the fired metas' constituents (post-wave, so no meta in
		// this wave saw another's suppression).
		for _, f := range fired {
			m := byPair[f.pk]
			for _, k := range f.spec.constituents {
				delete(m, k)
			}
		}
	}

	out := make([]*graph.Edge, 0, len(constituents)+len(metaEdges))
	out = append(out, metaEdges...)
	for _, pk := range pairOrder {
		for _, e := range byPair[pk] {
			out = append(out, e)
		}
	}
	return out
}

// lambdaBuildMetaEdge constructs one meta edge, aggregating allow_sources
// (deduplicated, first-seen order) and conditions (concatenated) across the present
// constituents in the spec's declared order — a port of
// MetaEdgeBaseProcessor._build_meta_edge. Property insertion order is is_traversable,
// allow_sources, conditions.
func lambdaBuildMetaEdge(pk lambdaPair, spec lambdaMetaSpec, m map[graph.EdgeKind]*graph.Edge) *graph.Edge {
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
