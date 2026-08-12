package eval

import "slices"

// This file holds the combination algebra IamPolicyEngine.Combine relies on: the
// grant/level/ceiling operators (applyCeiling, applyLevels, grantsOf,
// conjoinConditions, ...), the exact resource-pattern glob intersection ported
// from resource_pattern.py, and the ActionSet set operations. It is pure movement
// out of engine.go, which keeps the compile/combine core.

// grantsOf flattens the grants with the given Effect across a list of compiled
// policies (a guardrail attach level, or the boundary passed as a single policy).
// Ported from engine.py _allow_grants / _deny_grants.
func grantsOf(effect Effect, cps ...*CompiledPolicy) []Grant {
	var out []Grant
	for _, cp := range cps {
		if cp == nil {
			continue
		}
		for _, g := range cp.Grants {
			if g.Effect == effect {
				out = append(out, g)
			}
		}
	}
	return out
}

// applyLevels applies a per-level ceiling stack (intersection across levels,
// union within a level): each level's allow grants cap the surviving allows and
// its deny grants extend the deny list. An empty level (no allow grants) caps the
// allows to nothing — an SCP/RCP that permits nothing blocks everything. Ported
// from IamPolicyEngine._apply_levels (the levels branch; the Go API carries no
// flat single-level shorthand).
func (e *IamPolicyEngine) applyLevels(allows, denies []Grant, levels [][]*CompiledPolicy) ([]Grant, []Grant) {
	for _, level := range levels {
		allows = e.applyCeiling(allows, grantsOf(EffectAllow, level...))
		denies = append(denies, grantsOf(EffectDeny, level...)...)
	}
	return allows, denies
}

// guardrailPermitted returns the set of grants a guardrail (SCP/RCP) permits on
// its own — the across-level intersection of its allow grants, independent of
// identity. Empty when the guardrail is absent (it imposes no ceiling). Ported
// from IamPolicyEngine._guardrail_permitted (levels branch).
func (e *IamPolicyEngine) guardrailPermitted(levels [][]*CompiledPolicy) []Grant {
	if len(levels) == 0 {
		return nil
	}
	permitted := grantsOf(EffectAllow, levels[0]...)
	for _, level := range levels[1:] {
		permitted = e.applyCeiling(permitted, grantsOf(EffectAllow, level...))
	}
	return permitted
}

// anyPermitsAll reports whether any grant permits every action — a complement
// grant with an empty excluded set (complement of ∅). Ported from the
// `any(g.complement and not g.actions ...)` guardrail check in combine.
func anyPermitsAll(grants []Grant) bool {
	for _, g := range grants {
		if g.Complement && len(g.Actions) == 0 {
			return true
		}
	}
	return false
}

// indexGrant appends one logical EffectiveStatement. Query-time action views
// select matching grants lazily, avoiding one cached statement per catalog
// action for Action:"*" and NotAction policies.
func indexGrant(target *[]*EffectiveStatement, grant Grant) {
	indexGrantScoped(target, grant, false)
}

func indexGrantScoped(target *[]*EffectiveStatement, grant Grant, identityScoped bool) {
	if !grant.Complement && len(grant.Actions) == 0 {
		return
	}
	stmt := &EffectiveStatement{
		Actions:        grant.Actions,
		Resource:       grant.Resource,
		NotResource:    grant.NotResource,
		Condition:      grant.Condition,
		Source:         grant.Source,
		Complement:     grant.Complement,
		IdentityScoped: identityScoped,
	}
	*target = append(*target, stmt)
}

// applyCeiling caps allows to what ceiling also permits (boundary / SCP / RCP ∩).
// Ported from IamPolicyEngine._apply_ceiling.
//
// It is complement-aware, so a FullAWSAccess ceiling (a complement-of-∅ grant)
// imposes no action restriction without ever materializing the catalog:
// finite ∩ all = finite; all ∩ finite = finite; all ∩ all = all. Resource
// patterns are intersected exactly, and a surviving grant must satisfy both the
// identity and ceiling conditions (their conjunction).
func (e *IamPolicyEngine) applyCeiling(allows, ceiling []Grant) []Grant {
	var capped []Grant
	for _, grant := range allows {
		for _, limit := range ceiling {
			// Complement-aware intersection (Actions = excluded set when
			// Complement): finite ∩ finite = ∩; finite ∩ comp(E) = finite−E;
			// comp(E1) ∩ comp(E2) = comp(E1∪E2).
			var commonActions ActionSet
			var commonComp bool
			switch {
			case limit.Complement && len(limit.Actions) == 0:
				// FullAWSAccess: action intersection is the identity unchanged.
				// Reuse its immutable set instead of cloning every action for
				// every principal at every Organizations level.
				commonActions, commonComp = grant.Actions, grant.Complement
			case grant.Complement && len(grant.Actions) == 0:
				commonActions, commonComp = limit.Actions, limit.Complement
			case grant.Complement && limit.Complement:
				commonActions, commonComp = grant.Actions.union(limit.Actions), true
			case grant.Complement:
				commonActions, commonComp = limit.Actions.minus(grant.Actions), false
			case limit.Complement:
				commonActions, commonComp = grant.Actions.minus(limit.Actions), false
			default:
				commonActions, commonComp = grant.Actions.intersect(limit.Actions), false
			}
			if !commonComp && len(commonActions) == 0 {
				continue
			}
			resource, notResource, ok := intersectResource(grant, limit)
			if !ok {
				continue
			}
			capped = append(capped, Grant{
				Actions:     commonActions,
				Resource:    resource,
				NotResource: notResource,
				// A ceiling's allow may itself be conditional; the surviving grant
				// must satisfy BOTH the identity and ceiling conditions.
				Condition:  conjoinConditions(grant.Condition, limit.Condition),
				Source:     grant.Source,
				Effect:     EffectAllow,
				Complement: commonComp,
			})
		}
	}
	return capped
}

// intersectResource intersects a grant's resource constraint with a ceiling
// grant's. Ported from IamPolicyEngine._intersect_resource.
//
// Each side is either a positive Resource pattern or a NotResource exclusion (AWS
// treats them as mutually exclusive per statement, though a post-ceiling grant may
// carry both). It returns the surviving (resource, notResource); ok is false —
// the Python _EMPTY sentinel — when the positive patterns are disjoint, and the
// caller drops the pairing.
func intersectResource(grant, limit Grant) (resource *string, notResource *string, ok bool) {
	gPos, gNeg := grant.Resource, grant.NotResource
	lPos, lNeg := limit.Resource, limit.NotResource

	// Ceiling imposes no constraint -> grant unchanged.
	if isBroad(lPos) && lNeg == nil {
		return gPos, gNeg, true
	}
	// Grant unconstrained -> ceiling's constraint applies.
	if isBroad(gPos) && gNeg == nil {
		return lPos, lNeg, true
	}
	// Both positive -> exact pattern intersection.
	if gPos != nil && lPos != nil {
		inter, interOK := intersectPatterns(*gPos, *lPos)
		if !interOK {
			return nil, nil, false
		}
		return &inter, nil, true
	}
	// Grant positive, ceiling exclusion -> keep positive, carry the carve-out.
	if gPos != nil && lNeg != nil {
		return gPos, lNeg, true
	}
	// Grant exclusion, ceiling positive -> take ceiling positive, keep carve-out.
	if gNeg != nil && lPos != nil {
		return lPos, gNeg, true
	}
	// Both exclusions -> the union of exclusions. Representable as a single
	// NotResource only when one carve-out contains the other; otherwise keep the
	// grant's (rare; an over-approximation no worse than dropping).
	if gNeg != nil && lNeg != nil {
		inter, interOK := intersectPatterns(*gNeg, *lNeg)
		if interOK && inter == *gNeg {
			return nil, lNeg, true
		}
		if interOK && inter == *lNeg {
			return nil, gNeg, true
		}
		return nil, gNeg, true
	}
	return gPos, gNeg, true
}

// isBroad reports whether a resource pointer imposes no constraint — the Python
// `pattern in (None, "*")` test: a nil pointer (absent) or the "*" wildcard.
func isBroad(p *string) bool {
	return p == nil || *p == "*"
}

// conjoinConditions conjoins two IAM Condition blocks — the result requires
// *both* to hold. Ported from engine.py _conjoin_conditions.
//
// Different operator/key pairs are already ANDed by AWS, so merging the blocks is
// the conjunction. A same-operator-and-key collision unions the value lists (an
// OR over-approximation) — strictly tighter than dropping the ceiling's condition,
// and such collisions do not occur between an identity grant and its boundary/SCP
// in practice. The result never aliases a's or b's value slices, so a cached
// compiled policy is never mutated.
func conjoinConditions(a, b Condition) Condition {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	merged := make(Condition, len(a))
	for op, kv := range a {
		merged[op] = copyValues(kv)
	}
	for op, kv := range b {
		dst, present := merged[op]
		if !present {
			merged[op] = copyValues(kv)
			continue
		}
		for key, values := range kv {
			existing, has := dst[key]
			if !has {
				dst[key] = append([]string(nil), values...)
				continue
			}
			for _, val := range values {
				if !slices.Contains(existing, val) {
					existing = append(existing, val)
				}
			}
			dst[key] = existing
		}
	}
	return merged
}

// copyValues deep-copies one condition operator block (key -> values), cloning
// each value slice so the result never aliases the source's slices. An empty
// source slice clones to nil, matching the prior append([]string(nil), v...).
func copyValues(kv map[string][]string) map[string][]string {
	inner := make(map[string][]string, len(kv))
	for k, v := range kv {
		inner[k] = append([]string(nil), v...)
	}
	return inner
}

// --- resource-pattern intersection -----------------------------------------
//
// Exact intersection of two IAM resource patterns ('*'/'?' globs), ported from
// awshound/core/evaluation/iam_policy/resource_pattern.py (intersect). Kept
// file-local and unexported: the engine is the only caller (via
// intersectResource), and this avoids materializing the resource universe or
// colliding with a broader resource-pattern module should one be added later.
//
// '*' matches any run of characters (including empty) and '?' exactly one. The
// intersection is exact for every realistic ARN shape (prefix wildcards,
// mid-string region/account wildcards, prefix+suffix anchoring, exact ARNs);
// for the rare pair whose intersection is a non-empty *union* of globs (only
// constructible with leading-'*' patterns absent from anchored ARNs) it reports
// disjoint — the conservative direction for a ceiling (drop rather than invent).

// patResult is the memoized result of the intersection recursion: a glob string
// when ok, or the Python None (no intersection along this path) when not ok.
type patResult struct {
	s  string
	ok bool
}

// intersectPatterns returns the exact intersection glob of a and b, or ok=false
// (the Python DISJOINT sentinel) when they share no concrete resource or their
// intersection is not expressible as a single glob. Ported from
// resource_pattern.intersect.
func intersectPatterns(aRaw, bRaw string) (string, bool) {
	a := collapseStars([]rune(aRaw))
	b := collapseStars([]rune(bRaw))
	memo := make(map[[2]int]patResult)

	var rec func(i, j int) patResult
	rec = func(i, j int) patResult {
		key := [2]int{i, j}
		if res, done := memo[key]; done {
			return res
		}
		var result patResult
		switch {
		case i == len(a):
			if j == len(b) || allStars(b[j:]) {
				result = patResult{"", true}
			} else {
				result = patResult{"", false}
			}
		case j == len(b):
			if allStars(a[i:]) {
				result = patResult{"", true}
			} else {
				result = patResult{"", false}
			}
		case allStars(a[i:]):
			// a matches anything from here -> intersection is b's remainder.
			result = patResult{string(b[j:]), true}
		case allStars(b[j:]):
			result = patResult{string(a[i:]), true}
		default:
			ca, cb := a[i], b[j]
			switch {
			case ca == '*' && cb == '*':
				sub := rec(i+1, j+1)
				if sub.ok {
					result = patResult{"*" + sub.s, true}
				} else {
					result = patResult{"", false}
				}
			case ca == '*':
				// a-star matches empty, or absorbs b's next char (cb concrete).
				empty := rec(i+1, j)
				if empty.ok {
					result = empty
				} else if absorbed := rec(i, j+1); absorbed.ok {
					result = patResult{string(cb) + absorbed.s, true}
				} else {
					result = patResult{"", false}
				}
			case cb == '*':
				empty := rec(i, j+1)
				if empty.ok {
					result = empty
				} else if absorbed := rec(i+1, j); absorbed.ok {
					result = patResult{string(ca) + absorbed.s, true}
				} else {
					result = patResult{"", false}
				}
			default:
				m, mok := charIntersect(ca, cb)
				if !mok {
					result = patResult{"", false}
				} else if sub := rec(i+1, j+1); sub.ok {
					result = patResult{string(m) + sub.s, true}
				} else {
					result = patResult{"", false}
				}
			}
		}
		memo[key] = result
		return result
	}

	out := rec(0, 0)
	if !out.ok {
		return "", false
	}
	return string(collapseStars([]rune(out.s))), true
}

// collapseStars collapses runs of '*' into a single '*' ("a**b" == "a*b").
// Ported from resource_pattern._collapse.
func collapseStars(p []rune) []rune {
	out := make([]rune, 0, len(p))
	for i := 0; i < len(p); i++ {
		if p[i] == '*' {
			out = append(out, '*')
			for i+1 < len(p) && p[i+1] == '*' {
				i++
			}
		} else {
			out = append(out, p[i])
		}
	}
	return out
}

// allStars reports whether s is non-empty and every rune is '*'. Ported from
// resource_pattern._all_stars.
func allStars(s []rune) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c != '*' {
			return false
		}
	}
	return true
}

// charIntersect intersects two single non-'*' pattern runes (literals or '?'),
// returning ok=false when they cannot match the same character. Ported from
// resource_pattern._char_intersect.
func charIntersect(x, y rune) (rune, bool) {
	if x == '?' {
		return y, true
	}
	if y == '?' {
		return x, true
	}
	if x == y {
		return x, true
	}
	return 0, false
}

// --- ActionSet set algebra --------------------------------------------------
//
// The engine's complement resolution and ceiling intersection need union,
// intersection, and difference over action sets; types.go leaves this algebra to
// the engine port. Each operation returns a fresh set and never mutates its
// operands, so compiled grants (which may be shared across principals) stay
// immutable.

// union returns a new set containing every action in s or other.
func (s ActionSet) union(other ActionSet) ActionSet {
	out := make(ActionSet, len(s)+len(other))
	for a := range s {
		out[a] = struct{}{}
	}
	for a := range other {
		out[a] = struct{}{}
	}
	return out
}

// intersect returns a new set of the actions in both s and other.
func (s ActionSet) intersect(other ActionSet) ActionSet {
	small, large := s, other
	if len(large) < len(small) {
		small, large = large, small
	}
	out := make(ActionSet)
	for a := range small {
		if _, ok := large[a]; ok {
			out[a] = struct{}{}
		}
	}
	return out
}

// minus returns a new set of the actions in s but not other.
func (s ActionSet) minus(other ActionSet) ActionSet {
	out := make(ActionSet, len(s))
	for a := range s {
		if _, ok := other[a]; !ok {
			out[a] = struct{}{}
		}
	}
	return out
}

// addAll inserts every action into the set in place.
func (s ActionSet) addAll(actions []string) {
	for _, a := range actions {
		s[a] = struct{}{}
	}
}
