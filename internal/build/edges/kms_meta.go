// This file ports the two KMS meta-edge processors (core/graph/edges/meta/, the
// KmsKeyAll and KmsKeyRead entries) together with the wave-aware suppression the
// runtime framework (runtime/dag.py + runtime/edge_store.py) applies around them.
//
// Each meta edge fires at a (start, end) pair only when EVERY one of its
// constituent kinds is present at that pair, and its properties aggregate the
// constituents' allow_sources (deduplicated, order-preserving) and conditions
// (concatenated) exactly as MetaEdgeBaseProcessor._build_meta_edge does. When a
// meta fires it SUPPRESSES its constituents at that pair — they are removed from
// the surviving edge set in favour of the meta.
//
// Wave order. KMSKeyRead lists KMSKeyAll as a priority_predecessor, so the DAG
// topo-sort runs KMSKeyAll first (wave 1) and KMSKeyRead second (wave 2).
// Suppression is applied AFTER a whole wave completes, so KMSKeyAll reads the full
// constituent set before it suppresses, then KMSKeyRead reads the post-All state:
// at any (principal, key) pair where All fired (all eight constituents present),
// Decrypt/Encrypt/GenerateDataKey are already gone, so Read finds nothing and
// skips. Where All did not fire but the three crypto constituents are present,
// Read fires and consolidates them.
//
// Both KMS metas carry is_traversable=false (their Python bindings omit
// is_traversable=True, and MetaEdgeBaseProcessor always sets the property).
package edges

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/graph"
)

// kmsPair is a directed (start, end) endpoint pair used to group constituents.
type kmsPair struct {
	start string
	end   string
}

// kmsMetaSpec binds a meta edge kind to its is_traversable flag and its ordered
// constituent kinds. constituents doubles as the suppresses set (deleted at every
// pair where the meta fires), matching MetaEdgeBaseProcessor where suppresses ==
// constituents.
type kmsMetaSpec struct {
	kind         graph.EdgeKind
	traversable  bool
	constituents []graph.EdgeKind
}

// The two KMS meta specs. Constituent order follows the Python frozenset literal
// (it only affects allow_sources/conditions aggregation order, matching the
// legacy consolidator's declared order).
var (
	kmsKeyAll = kmsMetaSpec{
		kind: graph.KindKMSKeyAll,
		constituents: []graph.EdgeKind{
			graph.KindCanDecryptKMSKey,
			graph.KindCanEncryptKMSKey,
			graph.KindCanGenerateKMSDataKey,
			graph.KindCanCreateKMSGrant,
			graph.KindCanSelfGrantKMSOps,
			graph.KindCanModifyKMSKeyPolicy,
			graph.KindCanDisableKMSKey,
			graph.KindCanScheduleKMSKeyDeletion,
		},
	}
	kmsKeyRead = kmsMetaSpec{
		kind: graph.KindKMSKeyRead,
		constituents: []graph.EdgeKind{
			graph.KindCanDecryptKMSKey,
			graph.KindCanEncryptKMSKey,
			graph.KindCanGenerateKMSDataKey,
		},
	}
)

// kmsMetaWaves is the DAG wave assignment: ALL, then READ. Suppression runs at
// the end of each wave (see kmsApplyMetaWaves), so every meta in a wave reads the
// same pre-wave constituent state.
var kmsMetaWaves = [][]kmsMetaSpec{
	{kmsKeyAll},
	{kmsKeyRead},
}

// kmsApplyMetaWaves consolidates the constituent edges into the KMS meta edges and
// returns the final edge set: every meta edge that fired, plus every constituent
// that survived suppression. Constituents that no meta consumes (the account-level
// CanListKmsKeys edges, standalone CanCreateKMSGrant / lifecycle edges at partial
// pairs) pass through unchanged.
func kmsApplyMetaWaves(constituents []*graph.Edge) []*graph.Edge {
	// Group constituents by endpoint pair. (start, end, kind) is unique across the
	// constituent set, so a plain kind->edge map per pair loses nothing.
	byPair := make(map[kmsPair]map[graph.EdgeKind]*graph.Edge)
	var pairOrder []kmsPair
	for _, e := range constituents {
		pk := kmsPair{start: e.Start, end: e.End}
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
	for _, wave := range kmsMetaWaves {
		// Phase 1: fire every meta in the wave against the pre-wave state.
		type kmsFired struct {
			spec kmsMetaSpec
			pk   kmsPair
		}
		var fired []kmsFired
		for _, spec := range wave {
			for _, pk := range pairOrder {
				m := byPair[pk]
				if m == nil || !allPresent(m, spec.constituents) {
					continue
				}
				metaEdges = append(metaEdges, kmsBuildMetaEdge(pk, spec, m))
				fired = append(fired, kmsFired{spec: spec, pk: pk})
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

// kmsBuildMetaEdge constructs one meta edge, aggregating allow_sources
// (deduplicated, first-seen order) and conditions (concatenated) across the
// present constituents in the spec's declared order — a port of
// MetaEdgeBaseProcessor._build_meta_edge. Property insertion order is
// is_traversable, allow_sources, conditions.
func kmsBuildMetaEdge(pk kmsPair, spec kmsMetaSpec, m map[graph.EdgeKind]*graph.Edge) *graph.Edge {
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
