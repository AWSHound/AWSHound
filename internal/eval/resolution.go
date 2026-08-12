package eval

// This file ports AWSHound's attacker-favorable bias arbiter and the shared
// allow/deny statement resolver from core/evaluation/conditions/:
//
//   - bias.py                 -> BiasOutcome, ApplyConditionBias
//   - statement_resolution.py -> MatchedStatement, StatementResolutionResult,
//                                ResolveMatchedStatements, conditionRecord
//
// The condition walk that produces the Resolution these consume lives in
// conditions.go; every condition-aware evaluator routes its final allow/deny
// decision through ResolveMatchedStatements so the tri-state bias rule cannot drift.

// -------------------------------------------------------------------------
// Attacker-favorable bias (bias.py)
// -------------------------------------------------------------------------

// BiasOutcome is what to do with a statement after its Condition has resolved.
// Ported from bias.py Outcome (renamed to avoid confusion with PermissionOutcome
// in types.go).
type BiasOutcome int

const (
	// BiasDiscard drops the statement (an Allow that resolved FALSE, or any
	// non-TRUE Deny).
	BiasDiscard BiasOutcome = iota
	// BiasRetainClean keeps the statement unconditionally (its condition
	// resolved TRUE).
	BiasRetainClean
	// BiasRetainConditional keeps an Allow whose condition resolved UNKNOWN as a
	// conditional grant.
	BiasRetainConditional
)

// ApplyConditionBias decides a statement's fate given its effect and condition
// resolution. Ported from bias.py apply_condition_bias.
//
// Attack-path bias: UNKNOWN allows are retained as conditional; UNKNOWN denies
// are discarded (an attacker is assumed to avoid triggering an unknowable deny
// gate). This is the single place the rule lives, so it cannot drift across
// evaluators. An effect other than Allow/Deny is a caller bug (a compiled
// statement always has one) and panics, mirroring the Python ValueError.
func ApplyConditionBias(effect Effect, resolution Resolution) BiasOutcome {
	switch effect {
	case EffectAllow:
		switch resolution {
		case ResolutionTrue:
			return BiasRetainClean
		case ResolutionFalse:
			return BiasDiscard
		default:
			return BiasRetainConditional
		}
	case EffectDeny:
		if resolution == ResolutionTrue {
			return BiasRetainClean
		}
		// FALSE or UNKNOWN — drop the deny.
		return BiasDiscard
	default:
		panic("eval: unknown statement Effect: " + string(effect))
	}
}

// -------------------------------------------------------------------------
// Shared allow/deny arbiter (statement_resolution.py)
// -------------------------------------------------------------------------

// MatchedStatement is a policy statement already matched to the (action,
// resource) under evaluation, carrying just the condition and audit source the
// arbiter needs. Ported from statement_resolution.py MatchedStatement.
//
// Condition is nil for an unconditional statement. Source is the audit label
// (an ARN, or e.g. "trust/0"). The Python fast paths duck-type on Statement
// instances to avoid a wrapper allocation; the Go engine instead builds a slice
// of these small value structs, which is a single backing-array allocation.
type MatchedStatement struct {
	Condition Condition
	Source    string
}

// StatementResolutionResult is the outcome of resolving a set of matched
// allow/deny statements. Ported from statement_resolution.py
// StatementResolutionResult. Conditions is the auditable trace of every
// evaluated gating condition (resolved-true and unknown/defaulted alike),
// regardless of which branch ultimately grants; AllowSources reflects the
// deciding branch.
type StatementResolutionResult struct {
	Allowed      bool
	Denied       bool
	Conditions   []map[string]any
	AllowSources []string
	DenySources  []string
}

// ContextFactory lazily builds the RequestContext for a resolution. Ported from
// statement_resolution.py's ContextFactory. It is invoked only when at least one
// matched statement has a Condition, keeping the unconditional hot path free of
// the (expensive) context build. A nil factory is treated as the Python default
// (a blank context), which under attacker bias yields allowed=true with the full
// condition residual retained.
type ContextFactory func() *RequestContext

// blankContext is the shared empty context used when no matched statement has a
// condition (the resolver never reads it) or when a nil factory is supplied. Its
// nil maps read safely and every key resolves to UNKNOWN. Ported from
// statement_resolution.py _BLANK_CONTEXT.
var blankContext = &RequestContext{}

// ResolveMatchedStatements resolves matched allow/deny statements to a final
// allow/deny decision under attacker-favorable bias. Ported from
// statement_resolution.py resolve_matched_statements. Every condition-aware
// evaluator (identity, trust, S3, Lambda, KMS) routes through this so the
// tri-state bias rule cannot drift.
//
// Algorithm: (1) denies first — only a TRUE deny survives (UNKNOWN/FALSE denies
// drop); any surviving deny wins. (2) clean-allow short-circuit — any
// unconditional allow grants immediately. (3) resolve the remaining conditional
// allows: TRUE -> clean, UNKNOWN -> retained conditional (attacker bias),
// FALSE -> dropped. (4) a clean allow wins if present, else any conditional
// allow wins; the conditions trace carries every evaluated gating condition.
func ResolveMatchedStatements(matchedAllows, matchedDenies []MatchedStatement, contextFactory ContextFactory) StatementResolutionResult {
	needsContext := anyConditioned(matchedAllows) || anyConditioned(matchedDenies)
	ctx := blankContext
	if needsContext {
		if contextFactory != nil {
			ctx = contextFactory()
		}
	}

	// 1. Denies. Only TRUE denies survive bias; UNKNOWN/FALSE denies drop.
	denySources := collectCleanDenies(matchedDenies, ctx)
	if len(denySources) > 0 {
		return StatementResolutionResult{Denied: true, DenySources: denySources}
	}

	// 2. Clean-allow short-circuit: any allow with no Condition is
	// unconditional. Skip evaluating the other allow conditions.
	var unconditionalSources []string
	for _, stmt := range matchedAllows {
		if len(stmt.Condition) == 0 {
			unconditionalSources = append(unconditionalSources, stmt.Source)
		}
	}
	if len(unconditionalSources) > 0 {
		return StatementResolutionResult{Allowed: true, AllowSources: unconditionalSources}
	}

	// 3. Resolve the conditional allows (every remaining allow has a Condition).
	var cleanAllowSources []string
	var cleanRecords []map[string]any
	var conditionalSources []string
	var conditionalRecords []map[string]any
	for _, stmt := range matchedAllows {
		resolution := ResolveCondition(stmt.Condition, ctx)
		outcome := ApplyConditionBias(EffectAllow, resolution)
		switch outcome {
		case BiasRetainClean:
			cleanAllowSources = append(cleanAllowSources, stmt.Source)
			cleanRecords = append(cleanRecords, conditionRecord(stmt.Condition, ctx, resolution))
		case BiasRetainConditional:
			conditionalSources = append(conditionalSources, stmt.Source)
			conditionalRecords = append(conditionalRecords, conditionRecord(stmt.Condition, ctx, resolution))
		}
		// BiasDiscard: drop silently.
	}

	// 4. Decision. The trace is clean records then conditional records, in
	// matched order; AllowSources reflects the deciding branch.
	allRecords := append(append([]map[string]any(nil), cleanRecords...), conditionalRecords...)
	if len(cleanAllowSources) > 0 {
		return StatementResolutionResult{Allowed: true, AllowSources: cleanAllowSources, Conditions: allRecords}
	}
	if len(conditionalSources) > 0 {
		return StatementResolutionResult{Allowed: true, AllowSources: conditionalSources, Conditions: allRecords}
	}
	return StatementResolutionResult{}
}

// anyConditioned reports whether any matched statement carries a Condition.
func anyConditioned(statements []MatchedStatement) bool {
	for _, stmt := range statements {
		if len(stmt.Condition) > 0 {
			return true
		}
	}
	return false
}

// collectCleanDenies returns the sources of denies that apply: unconditional
// denies (fast path) and conditional denies whose condition resolves TRUE.
// Ported from statement_resolution.py _collect_clean_denies.
func collectCleanDenies(matchedDenies []MatchedStatement, ctx *RequestContext) []string {
	var sources []string
	for _, stmt := range matchedDenies {
		if len(stmt.Condition) == 0 {
			sources = append(sources, stmt.Source)
			continue
		}
		if ResolveCondition(stmt.Condition, ctx) == ResolutionTrue {
			sources = append(sources, stmt.Source)
		}
	}
	return sources
}

// conditionRecord is an auditable record of one grant-gating condition block.
// Ported from statement_resolution.py _condition_record. It surfaces, for an
// edge: the condition block, how it resolved ("true"/"false"/"unknown"), whether
// the grant relied on attacker-favorable defaulting (defaulted == resolution was
// UNKNOWN), and the value each referenced ${...} policy variable took (nil when
// unresolvable). The condition block is shallow-copied like Python's
// dict(condition) so the trace never aliases the statement's own map.
func conditionRecord(cond Condition, ctx *RequestContext, resolution Resolution) map[string]any {
	return map[string]any{
		"condition":        copyConditionShallow(cond),
		"resolution":       resolution.String(),
		"defaulted":        resolution == ResolutionUnknown,
		"policy_variables": resolveVariablesInCondition(cond, ctx),
	}
}

// copyConditionShallow returns a new top-level Condition map sharing the inner
// operator blocks, mirroring Python's dict(condition).
func copyConditionShallow(cond Condition) Condition {
	out := make(Condition, len(cond))
	for op, block := range cond {
		out[op] = block
	}
	return out
}
