package eval

import "strings"

// This file ports the IAM Condition engine's key resolver and condition walker
// from AWSHound's core/evaluation/conditions/ package:
//
//   - key_resolver.py        -> keyState/keyResolution, resolveKey and helpers
//   - condition_evaluator.py -> ResolveCondition and the operator/key walk
//
// The Kleene tristate (Resolution) and its logic live in types.go; the operator
// atoms and quantifiers in operators.go; the request context and policy-variable
// substitution in policy_variables.go. The attacker-favorable bias arbiter and the
// shared matched-statement resolver that consume the Resolution produced here live
// in resolution.go.

// -------------------------------------------------------------------------
// Key resolver (key_resolver.py)
// -------------------------------------------------------------------------

// keyState is the tri-state a condition key resolves to against a
// RequestContext. Ported from key_resolver.py KeyState.
//
//   - keyStatePresent: one or more concrete values (the atom dispatches
//     normally over them).
//   - keyStateAbsent: we have the relevant data and the key is genuinely
//     missing (the atom is called with nil -> typically FALSE; an IfExists
//     operator returns TRUE).
//   - keyStateUnknown: we lack the data needed to resolve, or the key is
//     runtime-only (SourceIp, MFA, CurrentTime, ...). Callers short-circuit; the
//     atom is not invoked.
type keyState int

const (
	keyStatePresent keyState = iota
	keyStateAbsent
	keyStateUnknown
)

// keyResolution is a resolved key: its state and any concrete value(s). Ported
// from key_resolver.py KeyResolution. values is populated only for
// keyStatePresent.
type keyResolution struct {
	state  keyState
	values []string
}

// runtimeOnlyKeys are pure request-time / cross-service context keys. Ported
// from key_resolver.py _RUNTIME_ONLY_KEYS. AWSHound is a static analyzer, so
// these are always UNKNOWN; attacker bias then drops UNKNOWN denies and retains
// UNKNOWN allows as conditional.
var runtimeOnlyKeys = map[string]bool{
	"aws:sourceip":                     true,
	"aws:vpcsourceip":                  true,
	"aws:sourcevpc":                    true,
	"aws:sourcevpce":                   true,
	"aws:currenttime":                  true,
	"aws:epochtime":                    true,
	"aws:tokenissuetime":               true,
	"aws:multifactorauthage":           true,
	"aws:multifactorauthpresent":       true,
	"aws:secretmaterialage":            true,
	"aws:secretsmanagerusage":          true,
	"aws:securetransport":              true,
	"aws:useragent":                    true,
	"aws:referer":                      true,
	"aws:sourcearn":                    true,
	"aws:sourceaccount":                true,
	"aws:sourceorgid":                  true,
	"aws:sourceorgpaths":               true,
	"aws:sourceidentity":               true,
	"aws:viaawsservice":                true,
	"aws:calledvia":                    true,
	"aws:calledviafirst":               true,
	"aws:calledvialast":                true,
	"aws:calledviachain":               true,
	"aws:tagkeys":                      true,
	"aws:transitivetagkeys":            true,
	"aws:principalservicename":         true,
	"aws:principalservicenameslist":    true,
	"aws:ec2instancesourceprivateipv4": true,
	"aws:ec2instancesourcevpc":         true,
}

// orgKeys are backed by org-tree data. Ported from key_resolver.py _ORG_KEYS.
// They resolve only when the context's OrgDataKnown flag is set.
var orgKeys = map[string]bool{
	"aws:principalorgid":    true,
	"aws:principalorgpaths": true,
	"aws:resourceorgid":     true,
	"aws:resourceorgpaths":  true,
}

// principalMetadataKeys are backed by per-principal metadata. Ported from
// key_resolver.py _PRINCIPAL_METADATA_KEYS. aws:userid is a member in the
// Python source too, but resolveKey routes it through resolveUserID earlier, so
// this set effectively governs aws:username and aws:principaltype.
var principalMetadataKeys = map[string]bool{
	"aws:userid":        true,
	"aws:username":      true,
	"aws:principaltype": true,
}

// resolveKey resolves a condition key against a request context, returning its
// tri-state and any concrete value(s). Ported from key_resolver.py resolve_key.
// Branch order is significant and mirrors the Python exactly (e.g. aws:userid is
// handled before the principal-metadata bucket).
func resolveKey(key string, ctx *RequestContext) keyResolution {
	keyLower := strings.ToLower(key)

	// Tag prefixes first: they classify as principal- vs resource-metadata for
	// the *Known-flag dispatch.
	if strings.HasPrefix(keyLower, "aws:principaltag/") {
		return resolvePrincipalTag(key, ctx)
	}
	if strings.HasPrefix(keyLower, "aws:resourcetag/") || strings.HasPrefix(keyLower, "ec2:resourcetag/") {
		return resolveResourceTag(key, ctx)
	}
	if strings.HasPrefix(keyLower, "aws:requesttag/") {
		return keyResolution{state: keyStateUnknown}
	}

	if runtimeOnlyKeys[keyLower] {
		return keyResolution{state: keyStateUnknown}
	}

	// iam:PassedToService is resolved when a PassRoleVia<service> processor
	// supplies the concrete target service via the context overlay; otherwise
	// UNKNOWN and attacker bias applies.
	if keyLower == "iam:passedtoservice" {
		if v, ok := ctx.Values["iam:passedtoservice"]; ok {
			return keyResolution{state: keyStatePresent, values: []string{v}}
		}
		return keyResolution{state: keyStateUnknown}
	}

	if keyLower == "aws:principalarn" {
		return resolvePrincipalArn(ctx)
	}
	if keyLower == "aws:userid" {
		return resolveUserID(ctx)
	}
	if orgKeys[keyLower] {
		return resolveOrgKey(keyLower, ctx)
	}
	if principalMetadataKeys[keyLower] {
		return resolvePrincipalMetadata(keyLower, ctx)
	}

	// aws:PrincipalAccount / aws:ResourceAccount are ARN-derived and populated
	// whenever the ARN is well-formed; a missing value is treated as UNKNOWN
	// (an unparseable ARN, extremely rare).
	if keyLower == "aws:principalaccount" || keyLower == "aws:resourceaccount" {
		if v, ok := ctx.Values[keyLower]; ok {
			return keyResolution{state: keyStatePresent, values: []string{v}}
		}
		return keyResolution{state: keyStateUnknown}
	}

	// Flat values cover explicitly supplied global/service keys. KnownKeys also
	// lets a service adapter assert that a key is genuinely absent for this form
	// of request, instead of falling through to attacker-biased UNKNOWN.
	if v, ok := ctx.Values[keyLower]; ok {
		return keyResolution{state: keyStatePresent, values: []string{v}}
	}
	if ctx.KnownKeys[keyLower] {
		return keyResolution{state: keyStateAbsent}
	}

	// Uncollected global, OIDC, SAML, service-specific, and custom keys remain
	// unknown to the general resolver.
	return keyResolution{state: keyStateUnknown}
}

// resolvePrincipalTag resolves aws:PrincipalTag/<name>. Ported from
// key_resolver.py _resolve_principal_tag. Flag-first: without the principal in
// the store the tag dict cannot be trusted (UNKNOWN); otherwise a hit is
// PRESENT and a miss is ABSENT. The tag name is the original-case key after the
// 17-character prefix.
func resolvePrincipalTag(key string, ctx *RequestContext) keyResolution {
	if !ctx.PrincipalKnown {
		return keyResolution{state: keyStateUnknown}
	}
	tagName := key[len("aws:PrincipalTag/"):]
	if v, ok := ctx.PrincipalTags[tagName]; ok {
		return keyResolution{state: keyStatePresent, values: []string{v}}
	}
	return keyResolution{state: keyStateAbsent}
}

// resolveResourceTag resolves aws:ResourceTag/<name>. Ported from
// key_resolver.py _resolve_resource_tag.
func resolveResourceTag(key string, ctx *RequestContext) keyResolution {
	if !ctx.ResourceKnown {
		return keyResolution{state: keyStateUnknown}
	}
	tagName := key[strings.IndexByte(key, '/')+1:]
	if v, ok := ctx.ResourceTags[tagName]; ok {
		return keyResolution{state: keyStatePresent, values: []string{v}}
	}
	return keyResolution{state: keyStateAbsent}
}

// resolvePrincipalArn resolves aws:PrincipalArn. Ported from key_resolver.py
// _resolve_principal_arn, including the role-form synthetic multi-value: for a
// role, both the literal role ARN and the assumed-role wildcard pattern
// (arn:aws:sts::ACCT:assumed-role/RoleName/*) are returned, so operators OR
// across the two forms real policies use. Do not "simplify" to one form.
func resolvePrincipalArn(ctx *RequestContext) keyResolution {
	arn, ok := ctx.Values["aws:principalarn"]
	if !ok {
		if ctx.PrincipalKnown {
			return keyResolution{state: keyStateAbsent}
		}
		return keyResolution{state: keyStateUnknown}
	}
	if strings.Contains(arn, ":role/") {
		prefix, rolePart, _ := strings.Cut(arn, ":role/")
		stsArn := strings.ReplaceAll(prefix, ":iam::", ":sts::") + ":assumed-role/" + rolePart + "/*"
		return keyResolution{state: keyStatePresent, values: []string{arn, stsArn}}
	}
	return keyResolution{state: keyStatePresent, values: []string{arn}}
}

// resolveUserID resolves aws:userid. Ported from key_resolver.py
// _resolve_userid, including the role-form synthetic multi-value: for an
// assumed-role/role principal both the bare RoleId and the RoleId:* session
// wildcard are returned (the session name is unknowable).
func resolveUserID(ctx *RequestContext) keyResolution {
	userid, ok := ctx.Values["aws:userid"]
	if !ok {
		if ctx.PrincipalKnown {
			return keyResolution{state: keyStateAbsent}
		}
		return keyResolution{state: keyStateUnknown}
	}
	principalType := strings.ToLower(ctx.Values["aws:principaltype"])
	if principalType == "assumedrole" || principalType == "role" {
		return keyResolution{state: keyStatePresent, values: []string{userid, userid + ":*"}}
	}
	return keyResolution{state: keyStatePresent, values: []string{userid}}
}

// resolveOrgKey resolves an org-tree key. Ported from key_resolver.py
// _resolve_org_key: UNKNOWN without org data, else PRESENT/ABSENT.
func resolveOrgKey(keyLower string, ctx *RequestContext) keyResolution {
	if !ctx.OrgDataKnown {
		return keyResolution{state: keyStateUnknown}
	}
	if v, ok := ctx.Values[keyLower]; ok {
		return keyResolution{state: keyStatePresent, values: []string{v}}
	}
	return keyResolution{state: keyStateAbsent}
}

// resolvePrincipalMetadata resolves a per-principal metadata key. Ported from
// key_resolver.py _resolve_principal_metadata: UNKNOWN without the principal,
// else PRESENT/ABSENT.
func resolvePrincipalMetadata(keyLower string, ctx *RequestContext) keyResolution {
	if !ctx.PrincipalKnown {
		return keyResolution{state: keyStateUnknown}
	}
	if v, ok := ctx.Values[keyLower]; ok {
		return keyResolution{state: keyStatePresent, values: []string{v}}
	}
	return keyResolution{state: keyStateAbsent}
}

// -------------------------------------------------------------------------
// Condition walker (condition_evaluator.py)
// -------------------------------------------------------------------------

const (
	quantForAnyValue  = "ForAnyValue"
	quantForAllValues = "ForAllValues"
)

// ResolveCondition resolves a Condition block to a tristate Resolution. Ported
// from condition_evaluator.py resolve_condition.
//
// Composition (Kleene three-valued logic): multiple operators AND together;
// multiple keys under one operator AND together; multiple policy values for one
// key OR together (inside the atom); a multi-valued context against a
// non-quantified operator auto-promotes to ForAnyValue. An absent/empty
// condition is TRUE. The walker does not embed bias — callers apply
// ApplyConditionBias to the result to decide statement fate.
//
// The result is independent of Go map iteration order: the operator- and
// key-level combinators are commutative AND (FALSE dominates, UNKNOWN beats
// TRUE), so it is deterministic despite the randomized map walk. No
// memoization: an earlier Python version cached by id(context) and returned
// stale resolutions after GC reused an address, producing non-deterministic
// edge counts.
func ResolveCondition(cond Condition, ctx *RequestContext) Resolution {
	if len(cond) == 0 {
		return ResolutionTrue
	}
	result := ResolutionTrue
	for operatorName, keyValueMap := range cond {
		result = result.And(resolveOperator(operatorName, keyValueMap, ctx))
		if result == ResolutionFalse {
			return ResolutionFalse
		}
	}
	return result
}

// resolveOperator resolves one operator entry; keys under one operator AND
// together. Ported from condition_evaluator.py _resolve_operator. An unknown or
// unsupported operator resolves to UNKNOWN. (The Python isinstance(dict) guard
// is unnecessary: a parsed Condition's operator block is always a typed map.)
func resolveOperator(operatorName string, keyValueMap map[string][]string, ctx *RequestContext) Resolution {
	quantifier, nameAfterQuantifier := stripQuantifier(operatorName)
	baseOp, ifExists := stripIfExists(nameAfterQuantifier)

	if unsupportedOperators[baseOp] {
		return ResolutionUnknown
	}
	entry, ok := operatorTable[baseOp]
	if !ok {
		return ResolutionUnknown
	}

	result := ResolutionTrue
	for key, policyValues := range keyValueMap {
		result = result.And(resolveKeyValue(key, policyValues, entry, ifExists, quantifier, ctx))
		if result == ResolutionFalse {
			return ResolutionFalse
		}
	}
	return result
}

// resolveKeyValue resolves one (key, policy_values) pair for a given operator.
// Ported from condition_evaluator.py _resolve_key.
func resolveKeyValue(key string, policyValues []string, entry operatorEntry, ifExists bool, quantifier string, ctx *RequestContext) Resolution {
	// Null inspects key presence directly rather than comparing values, so it
	// bypasses the standard atom dispatch (and policy-variable substitution).
	if entry.isNull {
		return resolveNull(key, policyValues, ctx)
	}

	// Substitute ${...} policy variables in each policy value before comparing.
	// An unresolvable variable collapses the operator to UNKNOWN — attacker
	// bias then retains the allow as conditional rather than dropping it.
	substituted := make([]string, 0, len(policyValues))
	for _, v := range policyValues {
		if strings.Contains(v, "${") {
			sub, ok := substituteInString(v, ctx, true)
			if !ok {
				return ResolutionUnknown
			}
			substituted = append(substituted, sub)
		} else {
			substituted = append(substituted, v)
		}
	}
	policyValues = substituted

	kr := resolveKey(key, ctx)

	switch kr.state {
	case keyStateUnknown:
		// IfExists does not help: it short-circuits on known absence, not on
		// data we lack.
		return ResolutionUnknown

	case keyStateAbsent:
		if ifExists {
			// IfExists with an absent key is trivially TRUE; negation does not
			// apply because the operator was never evaluated.
			return ResolutionTrue
		}
		var r Resolution
		switch quantifier {
		case quantForAllValues:
			r = ResolutionTrue // vacuous TRUE: ForAllValues over the empty set
		case quantForAnyValue:
			r = ResolutionFalse // OR over the empty set
		default:
			r = entry.atom(policyValues, nil)
		}
		if entry.negated {
			return r.Not()
		}
		return r

	default: // keyStatePresent
		contextValues := kr.values
		var r Resolution
		switch {
		case quantifier == quantForAllValues:
			r = forAllValues(entry.atom, policyValues, contextValues)
		case quantifier == quantForAnyValue || len(contextValues) > 1:
			// A bare operator on multi-valued context auto-promotes to
			// ForAnyValue (AWS semantics).
			r = forAnyValue(entry.atom, policyValues, contextValues)
		default:
			v := contextValues[0]
			r = entry.atom(policyValues, &v)
		}
		if entry.negated {
			return r.Not()
		}
		return r
	}
}

// resolveNull resolves the Null operator: it tests whether the key is absent
// from context. Ported from condition_evaluator.py _resolve_null. Null:true
// asserts the key is absent; Null:false asserts it is present. An unknowable key
// is UNKNOWN. Policy variables are not substituted for Null.
func resolveNull(key string, policyValues []string, ctx *RequestContext) Resolution {
	kr := resolveKey(key, ctx)
	if kr.state == keyStateUnknown {
		return ResolutionUnknown
	}
	isAbsent := kr.state == keyStateAbsent
	expectingAbsent := false
	for _, v := range policyValues {
		if strings.ToLower(v) == "true" {
			expectingAbsent = true
			break
		}
	}
	if expectingAbsent == isAbsent {
		return ResolutionTrue
	}
	return ResolutionFalse
}

// stripQuantifier splits a ForAnyValue: / ForAllValues: prefix from an operator
// name. Ported from condition_evaluator.py _strip_quantifier; the empty string
// stands for the Python None (no quantifier).
func stripQuantifier(name string) (quantifier, rest string) {
	if strings.HasPrefix(name, "ForAnyValue:") {
		return quantForAnyValue, name[len("ForAnyValue:"):]
	}
	if strings.HasPrefix(name, "ForAllValues:") {
		return quantForAllValues, name[len("ForAllValues:"):]
	}
	return "", name
}

// stripIfExists splits a trailing IfExists modifier from an operator name.
// Ported from condition_evaluator.py _strip_if_exists.
func stripIfExists(name string) (base string, ifExists bool) {
	if strings.HasSuffix(name, "IfExists") {
		return name[:len(name)-len("IfExists")], true
	}
	return name, false
}
