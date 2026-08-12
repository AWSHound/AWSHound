package eval

import (
	"net/netip"
	"strconv"
	"strings"
)

// atomFn is one IAM condition operator atom: a pure function of the policy
// values and a single request-context value. Ported from operators.py, where
// each atom is (policy_values, context_value) -> Resolution.
//
// ctxValue is nil when the key is known to be absent (the Python None); most
// atoms return FALSE for a nil value. UNKNOWN never reaches an atom — the key
// resolver short-circuits unknowable keys before dispatch. All context and
// policy values are strings here (the Go policy/condition parser coerces JSON
// bool/number scalars to their textual form at parse time), so the Python
// _string_of coercion is unnecessary; the Bool/Numeric atoms compare on the
// already-textual form exactly as _string_of would have produced.
//
// Multi-valued context is handled by the forAnyValue/forAllValues quantifiers,
// not the atoms.
type atomFn func(policyValues []string, ctxValue *string) Resolution

// operatorEntry maps an operator name to its base atom, whether the operator
// negates the atom's result, and whether it is the special Null operator (which
// inspects key presence rather than comparing values). Ported from
// condition_evaluator.py _OPERATOR_TABLE, which stores (atom, negated) tuples;
// Null is broken out as isNull because Go func values are not comparable, so the
// Python `atom_fn is ops.null_op` identity check becomes a flag.
type operatorEntry struct {
	atom    atomFn
	negated bool
	isNull  bool
}

// operatorTable maps a base operator name (quantifier and IfExists suffix
// already stripped) to its entry. Ported from condition_evaluator.py
// _OPERATOR_TABLE. Names are case-sensitive — AWS treats them so in policy
// documents. Operators not in this table (and not in unsupportedOperators)
// resolve to UNKNOWN.
var operatorTable = map[string]operatorEntry{
	"StringEquals":              {atom: stringEquals},
	"StringNotEquals":           {atom: stringEquals, negated: true},
	"StringEqualsIgnoreCase":    {atom: stringEqualsIgnoreCase},
	"StringNotEqualsIgnoreCase": {atom: stringEqualsIgnoreCase, negated: true},
	"StringLike":                {atom: stringLike},
	"StringNotLike":             {atom: stringLike, negated: true},
	// Arn* reuse the string atoms: AWS treats ArnEquals as StringEquals and ArnLike
	// as StringLike scoped to ARNs (operators.py arn_equals / arn_like).
	"ArnEquals":    {atom: stringEquals},
	"ArnNotEquals": {atom: stringEquals, negated: true},
	"ArnLike":      {atom: stringLike},
	"ArnNotLike":   {atom: stringLike, negated: true},
	// Bool: values are already textual, so boolean equality is case-insensitive
	// membership — identical to StringEqualsIgnoreCase (operators.py bool_op).
	"Bool":             {atom: stringEqualsIgnoreCase},
	"Null":             {isNull: true},
	"NumericEquals":    {atom: numericEquals},
	"NumericNotEquals": {atom: numericEquals, negated: true},
	// Date*: v1 treats DateEquals as literal string equality on ISO-8601 form; date
	// range operators short-circuit to UNKNOWN vs unknowable keys (operators.py date_equals).
	"DateEquals":    {atom: stringEquals},
	"DateNotEquals": {atom: stringEquals, negated: true},
	"IpAddress":     {atom: ipAddress},
	"NotIpAddress":  {atom: ipAddress, negated: true},
}

// unsupportedOperators are range/binary operators intentionally kept out of v1.
// Ported from condition_evaluator.py _UNSUPPORTED_OPERATORS. They are almost
// always paired with unknowable keys (aws:CurrentTime), so they would
// short-circuit to UNKNOWN at the resolver anyway; listing them explicitly
// avoids a silent treat-as-unknown-key when the key happens to be one we do
// populate. They resolve to UNKNOWN.
var unsupportedOperators = map[string]bool{
	"NumericLessThan":          true,
	"NumericLessThanEquals":    true,
	"NumericGreaterThan":       true,
	"NumericGreaterThanEquals": true,
	"DateLessThan":             true,
	"DateLessThanEquals":       true,
	"DateGreaterThan":          true,
	"DateGreaterThanEquals":    true,
	"BinaryEquals":             true,
}

// stringEquals is case-sensitive literal equality; "*" is not a wildcard.
// Ported from operators.py string_equals.
func stringEquals(policyValues []string, ctxValue *string) Resolution {
	if ctxValue == nil {
		return ResolutionFalse
	}
	for _, v := range policyValues {
		if v == *ctxValue {
			return ResolutionTrue
		}
	}
	return ResolutionFalse
}

// stringEqualsIgnoreCase is case-insensitive literal equality. Ported from
// operators.py string_equals_ignore_case.
func stringEqualsIgnoreCase(policyValues []string, ctxValue *string) Resolution {
	if ctxValue == nil {
		return ResolutionFalse
	}
	ctx := strings.ToLower(*ctxValue)
	for _, v := range policyValues {
		if strings.ToLower(v) == ctx {
			return ResolutionTrue
		}
	}
	return ResolutionFalse
}

// stringLike is a case-sensitive glob match using '*' and '?'. Ported from
// operators.py string_like, which uses fnmatch.fnmatchcase. It reuses this
// package's fnmatch matcher (catalog.go compileActionGlob/matchActionGlob),
// which faithfully mirrors CPython fnmatch.translate (including '[seq]' /
// '[!seq]' classes) and is case-sensitive — identical semantics to
// fnmatchcase, so StringLike and the catalog's action-pattern expansion share
// one matcher and cannot drift.
func stringLike(policyValues []string, ctxValue *string) Resolution {
	if ctxValue == nil {
		return ResolutionFalse
	}
	for _, pattern := range policyValues {
		if compileGlobCached(pattern).match(*ctxValue) {
			return ResolutionTrue
		}
	}
	return ResolutionFalse
}

// numericEquals is numeric equality. Ported from operators.py numeric_equals.
// Matching the Python try/except, every policy value is parsed before any
// membership test: if the context value or ANY policy value fails to parse as a
// float, the whole atom is FALSE (Python's list comprehension raises and the
// except returns FALSE). Surrounding whitespace is trimmed to approximate
// Python float()'s whitespace tolerance.
func numericEquals(policyValues []string, ctxValue *string) Resolution {
	if ctxValue == nil {
		return ResolutionFalse
	}
	ctx, err := strconv.ParseFloat(strings.TrimSpace(*ctxValue), 64)
	if err != nil {
		return ResolutionFalse
	}
	nums := make([]float64, len(policyValues))
	for i, v := range policyValues {
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return ResolutionFalse
		}
		nums[i] = n
	}
	for _, n := range nums {
		if ctx == n {
			return ResolutionTrue
		}
	}
	return ResolutionFalse
}

// ipAddress is a CIDR-membership check. Ported from operators.py ip_address.
// The context value must parse as an IP address; each policy value is a CIDR
// (or a bare address, treated as a full-length prefix, matching Python's
// ip_network(strict=False)). A policy value that does not parse is skipped. As
// with Python, an IPv4 address is never considered inside an IPv6 prefix (and
// vice versa). Every IP-comparable global key (aws:SourceIp, ...) is
// runtime-only and resolves to UNKNOWN, so this atom is effectively never
// reached with a real value.
func ipAddress(policyValues []string, ctxValue *string) Resolution {
	if ctxValue == nil {
		return ResolutionFalse
	}
	addr, err := netip.ParseAddr(*ctxValue)
	if err != nil {
		return ResolutionFalse
	}
	for _, cidr := range policyValues {
		prefix, ok := parseCIDRLoose(cidr)
		if !ok {
			continue
		}
		if prefix.Contains(addr) {
			return ResolutionTrue
		}
	}
	return ResolutionFalse
}

// parseCIDRLoose parses a CIDR, or a bare IP address as a host-length prefix.
// It mirrors Python ipaddress.ip_network(cidr, strict=False): host bits set in
// a prefix are tolerated (netip.Prefix.Contains masks internally), and a bare
// address becomes a /32 or /128. The netmask form ("a.b.c.0/255.255.255.0")
// that Python also accepts is not supported; it is vanishingly rare in IAM and
// this atom is effectively unreachable in practice.
func parseCIDRLoose(cidr string) (netip.Prefix, bool) {
	if strings.Contains(cidr, "/") {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p, true
	}
	a, err := netip.ParseAddr(cidr)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// forAnyValue reports whether at least one context value satisfies the atom.
// Ported from modifiers.py for_any_value: an OR (kleene_or_any) over the
// context values, so an empty context is FALSE. Short-circuits on TRUE.
func forAnyValue(atom atomFn, policyValues, contextValues []string) Resolution {
	result := ResolutionFalse
	for i := range contextValues {
		v := contextValues[i]
		result = result.Or(atom(policyValues, &v))
		if result == ResolutionTrue {
			return ResolutionTrue
		}
	}
	return result
}

// forAllValues reports whether every context value satisfies the atom. Ported
// from modifiers.py for_all_values: an AND (kleene_and_all) over the context
// values, so an empty context is vacuously TRUE. Short-circuits on FALSE. The
// vacuous-truth rule is a privesc footgun; the key resolver guarantees this is
// only reached with a context known to be genuinely (not unknowably) empty.
func forAllValues(atom atomFn, policyValues, contextValues []string) Resolution {
	result := ResolutionTrue
	for i := range contextValues {
		v := contextValues[i]
		result = result.And(atom(policyValues, &v))
		if result == ResolutionFalse {
			return ResolutionFalse
		}
	}
	return result
}
