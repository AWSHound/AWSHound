package eval

import (
	"regexp"
	"strings"
)

// RequestContext is the known request-context data used to resolve condition
// keys and substitute policy variables. Ported field-for-field from
// core/evaluation/policy_variables.py PolicyVariableContext.
//
// It answers, for a given (principal, action, resource) under evaluation, "what
// value(s) does condition key aws:X take?" — but only for the keys AWSHound
// statically knows. The tri-state mapping of a key to PRESENT/ABSENT/UNKNOWN is
// produced by resolveKey (conditions.go); this type only holds the raw data and
// the *Known flags that drive that mapping.
//
// The *Known flags distinguish "we ingested the data and the key is genuinely
// absent" (Known=true, value missing -> ABSENT -> the atom sees None and the
// condition typically resolves FALSE) from "we did not ingest the data so we
// cannot tell" (Known=false -> UNKNOWN, where attacker-favorable bias takes
// over). The zero value (nil maps, all flags false) is a valid blank context in
// which every key resolves to UNKNOWN; reads from its nil maps are safe.
//
// Values and KnownKeys keys are lower-cased. KnownKeys records service-specific
// keys whose presence/absence this request form can determine. Tag names in
// PrincipalTags/ResourceTags keep their original case (AWS tag keys are
// case-sensitive). The store/context-builder layer populates these fields.
type RequestContext struct {
	Values         map[string]string
	KnownKeys      map[string]bool
	PrincipalTags  map[string]string
	ResourceTags   map[string]string
	PrincipalKnown bool
	ResourceKnown  bool
	OrgDataKnown   bool
}

// variableRe matches an IAM policy variable ${...}. Ported from
// policy_variables.py _VARIABLE_RE. The body is one-or-more non-'}' characters,
// so nested braces are not recognized (matching AWS and the Python engine).
var variableRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// variableLiterals are the ${...} escape sequences that stand for a literal
// character rather than a context lookup. Ported from policy_variables.py
// _VARIABLE_LITERALS: ${*} -> "*", ${?} -> "?", ${$} -> "$".
var variableLiterals = map[string]string{"*": "*", "?": "?", "$": "$"}

// multivaluedContextKeys are global context keys documented as multivalued,
// which AWS forbids as policy variables. Ported from policy_variables.py
// _MULTIVALUED_CONTEXT_KEYS. get() returns absent for these, and substitution
// refuses to apply a default for them.
var multivaluedContextKeys = map[string]bool{
	"aws:calledvia":                 true,
	"aws:principalorgpaths":         true,
	"aws:principalservicenameslist": true,
	"aws:tagkeys":                   true,
	"aws:transitivetagkeys":         true,
}

// get returns a known context value for key, if available. Ported from
// PolicyVariableContext.get. The second result is false when the key has no
// known value (the Python None) — including the multivalued-key case and a
// missing tag. Tag lookups slice the original-case key after the (case-folded)
// prefix so the case-sensitive tag name is preserved; flat lookups use the
// lower-cased key.
func (c *RequestContext) get(key string) (string, bool) {
	keyLower := strings.ToLower(key)

	if multivaluedContextKeys[keyLower] {
		return "", false
	}

	const principalTagPrefix = "aws:principaltag/"
	if strings.HasPrefix(keyLower, principalTagPrefix) {
		tagKey := key[len(principalTagPrefix):]
		v, ok := c.PrincipalTags[tagKey]
		return v, ok
	}

	const resourceTagPrefix = "aws:resourcetag/"
	if strings.HasPrefix(keyLower, resourceTagPrefix) {
		tagKey := key[len(resourceTagPrefix):]
		v, ok := c.ResourceTags[tagKey]
		return v, ok
	}

	v, ok := c.Values[keyLower]
	return v, ok
}

// HasPolicyVariables reports whether a pattern contains IAM policy variable
// syntax. Ported from policy_variables.py has_policy_variables; a None pattern
// maps to the empty string, which contains no "${".
func HasPolicyVariables(pattern string) bool {
	return strings.Contains(pattern, "${")
}

// substituteInString substitutes ${...} policy variables anywhere in text.
// Ported from policy_variables.py substitute_in_string.
//
// The second result is false when at least one ${...} reference cannot be
// resolved and has no usable default — the Python None return, which the caller
// treats as UNKNOWN (for a condition value) or "matches no resource" (for an ARN
// pattern). It returns (text, true) unchanged when variables are disabled or the
// text has no "${". A ${literal} escape (${*}, ${?}, ${$}) expands to the
// literal character; a ${key} resolves against the context, falling back to a
// declared default (key,'default') only when the key is not multivalued.
func substituteInString(text string, ctx *RequestContext, variablesEnabled bool) (string, bool) {
	if !variablesEnabled || !strings.Contains(text, "${") {
		return text, true
	}

	unresolved := false
	result := variableRe.ReplaceAllStringFunc(text, func(match string) string {
		// match is the full "${...}"; strip the ASCII "${" prefix and "}"
		// suffix to recover the same text as the regex's group(1).
		expression := strings.TrimSpace(match[2 : len(match)-1])
		if literal, ok := variableLiterals[expression]; ok {
			return literal
		}
		key, def, hasDefault := parseVariableExpression(expression)
		if v, ok := ctx.get(key); ok {
			return v
		}
		if hasDefault && !multivaluedContextKeys[strings.ToLower(key)] {
			return def
		}
		unresolved = true
		return ""
	})
	if unresolved {
		return "", false
	}
	return result, true
}

// ResolvePolicyVariables resolves IAM policy variables in an ARN resource
// pattern. Ported from policy_variables.py resolve_policy_variables.
//
// AWS only substitutes variables in the ARN resource portion (the 6th
// colon-separated field). Non-ARN inputs, variables-disabled, and variable-free
// patterns are returned unchanged with ok=true. The second result is false when
// a variable is unresolved (the Python None) — the pattern then matches no
// concrete resource. Callers guard a nil/None pattern before calling (Python's
// None-input -> None case); an empty pattern here contains no "${" and returns
// ("", true).
func ResolvePolicyVariables(pattern string, ctx *RequestContext, variablesEnabled bool) (string, bool) {
	if !variablesEnabled || !strings.Contains(pattern, "${") {
		return pattern, true
	}

	parts := strings.SplitN(pattern, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return pattern, true
	}

	substituted, ok := substituteInString(parts[5], ctx, true)
	if !ok {
		return "", false
	}
	parts[5] = substituted
	return strings.Join(parts, ":"), true
}

// resolveVariablesInCondition maps each ${...} policy variable referenced in
// condition to the value the request context resolves it to. Ported from
// policy_variables.py resolve_variables_in_condition.
//
// The value is a nil *string when the variable is unresolved (no known context
// value and no usable default) — the Python None — so the auditable conditions
// trace can report "which policy variables were used, and what value did each
// take?". The output is keyed by the full ${...} token. It is order-independent:
// each distinct token maps to a single deterministic value regardless of the
// map iteration order over the condition.
func resolveVariablesInCondition(condition Condition, ctx *RequestContext) map[string]*string {
	out := map[string]*string{}
	if len(condition) == 0 {
		return out
	}

	scan := func(text string) {
		for _, m := range variableRe.FindAllStringSubmatch(text, -1) {
			token := m[0]
			expression := strings.TrimSpace(m[1])
			if _, isLiteral := variableLiterals[expression]; isLiteral {
				continue
			}
			key, def, hasDefault := parseVariableExpression(expression)
			if v, ok := ctx.get(key); ok {
				vv := v
				out[token] = &vv
				continue
			}
			if hasDefault && !multivaluedContextKeys[strings.ToLower(key)] {
				dd := def
				out[token] = &dd
				continue
			}
			out[token] = nil
		}
	}

	for _, operatorBlock := range condition {
		for condKey, condValues := range operatorBlock {
			scan(condKey)
			for _, item := range condValues {
				scan(item)
			}
		}
	}
	return out
}

// parseVariableExpression parses a "key" or "key, 'default'" variable
// expression. Ported from policy_variables.py _parse_variable_expression. The
// third result is false when no default clause is present (the Python None
// default). A present default has any surrounding matching single/double quotes
// stripped; key and default are both trimmed.
func parseVariableExpression(expression string) (key, def string, hasDefault bool) {
	idx := strings.Index(expression, ",")
	if idx < 0 {
		return strings.TrimSpace(expression), "", false
	}

	key = strings.TrimSpace(expression[:idx])
	def = strings.TrimSpace(expression[idx+1:])
	if len(def) >= 2 && def[0] == def[len(def)-1] && (def[0] == '\'' || def[0] == '"') {
		def = def[1 : len(def)-1]
	}
	return key, def, true
}
