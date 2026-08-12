package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// This file ports the shared plumbing of AWSHound's resource-policy evaluators —
// the cross-account access layer that composes with the identity side. The
// S3-, Lambda-, and trust-specific logic lives in resource_s3.go,
// resource_lambda.go, and trust.go respectively; the pure matching helpers and
// composition seams they all share live here.
//
// Ported from:
//   - core/evaluation/_helpers.py        -> actionPatternMatches, principalBlockMatches,
//                                            accountIDFromARN, isServicePrincipalARN. Its
//                                            resource_matches / arn_pattern_to_regex ARN
//                                            matcher is the shared regex-based
//                                            resourceMatches (evaluator.go) — the single
//                                            ARN-pattern matcher, used here too.
//   - the `iam_evaluator: PolicyEvaluator` dependency of the S3/Lambda
//     evaluators -> the IdentityEvaluator seam
//   - store.get_policy_variable_context   -> the ContextBuilder seam
//
// The identity policy-document AST and its (URL-decoding) parser live in
// policy.go; the condition engine and the shared allow/deny arbiter
// (ResolveMatchedStatements) in conditions.go.

// -------------------------------------------------------------------------
// Composition seams
// -------------------------------------------------------------------------

// IdentityEvaluator is the identity-policy side the S3 and Lambda resource
// evaluators compose with. It is the single method the Python evaluators need
// from their `iam_evaluator: PolicyEvaluator`: whether a principal's identity
// policies (with permissions boundary, SCP, and RCP ceilings already applied)
// allow an action on a resource.
//
// The identity kernel's *PolicyEvaluator does NOT satisfy this interface
// directly: its CanPerformAction carries an extra *RequestContext argument and
// returns a *PermissionCheckResult. Callers adapt it with IdentityFunc — a
// closure that supplies the context and dereferences the result — as
// internal/build/edges does (its iamIdentity helper) when wiring the S3 and
// Lambda evaluators.
type IdentityEvaluator interface {
	CanPerformAction(principalArn, action, resourceArn string) PermissionCheckResult
}

// IdentityFunc adapts a plain function to the IdentityEvaluator interface, so a
// bound method whose signature does not exactly match (or a test stub) can be
// supplied without a wrapper type.
type IdentityFunc func(principalArn, action, resourceArn string) PermissionCheckResult

// CanPerformAction implements IdentityEvaluator.
func (f IdentityFunc) CanPerformAction(principalArn, action, resourceArn string) PermissionCheckResult {
	return f(principalArn, action, resourceArn)
}

// ContextBuilder builds the RequestContext for a (principal, action, resource)
// triple — the seam onto store.get_policy_variable_context, which the Python
// resource evaluators call to resolve policy variables in Resource patterns and
// condition keys. A nil ContextBuilder (or one that returns nil) yields a blank
// context in which every key is UNKNOWN, matching the Python None-context path
// under attacker-favorable bias.
type ContextBuilder func(principalArn, action, resourceArn string) *RequestContext

// newContextMemo returns a memoized context accessor that builds the
// RequestContext at most once via builder(principal, action, resource), falling
// back to blankContext when builder is nil or yields nil. It mirrors the way the
// Python bucket-policy / resource-policy checks lazily build a single
// `variable_context` and share it between Resource-pattern substitution and the
// condition resolver's context factory — so the (expensive) context build
// happens at most once per check and only when actually needed.
func newContextMemo(builder ContextBuilder, principalArn, action, resourceArn string) ContextFactory {
	var cached *RequestContext
	built := false
	return func() *RequestContext {
		if !built {
			built = true
			if builder != nil {
				cached = builder(principalArn, action, resourceArn)
			}
			if cached == nil {
				cached = blankContext
			}
		}
		return cached
	}
}

// policyDecision is the allow/deny/conditions triple a single resource-policy
// (or IAM) check yields. It is the Go form of the {"allowed", "denied",
// "conditions"} dict the Python _check_bucket_policy / _check_resource_policy /
// _check_iam_policies helpers return.
type policyDecision struct {
	allowed    bool
	denied     bool
	conditions []map[string]any
}

// ParseResourcePolicy parses a resource-based policy document that is *plain
// JSON* — an S3 bucket policy (s3:GetBucketPolicy) or a Lambda resource policy
// (lambda:GetPolicy), each carried as a raw JSON string that is NOT
// percent-encoded. Use this, not ParsePolicyDocument, for those documents:
// ParsePolicyDocument first url-unescapes its input, which would corrupt a bucket
// policy whose value happens to contain a literal "%XX" sequence. (IAM identity
// documents and role trust policies from GetAccountAuthorizationDetails ARE
// url-encoded and must still go through ParsePolicyDocument.)
//
// This mirrors the Python resource evaluators, which json.loads the string
// directly. An empty/whitespace input returns (nil, nil): no policy, the Python
// falsy-document short-circuit.
func ParseResourcePolicy(raw []byte) (*Policy, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("eval: parse resource policy: %w", err)
	}
	return &p, nil
}

// -------------------------------------------------------------------------
// Action / principal matching (_helpers.py)
// -------------------------------------------------------------------------
//
// ARN-pattern matching lives in evaluator.go as the single regex-based
// resourceMatches (the faithful port of trust_policy.arn_pattern_to_regex /
// resource_matches). The action and principal matchers below call into it.

// actionPatternMatches reports whether a concrete action matches an action
// pattern. Ported from _helpers.action_matches, including its exact branch order:
// "*" matches all; a service-scoped ":*" wildcard matches when the service
// prefixes are equal (case-insensitively); a variable-free pattern is a
// case-insensitive literal comparison; otherwise a case-insensitive regex match
// via the shared arnPatternRegex (Python's action_matches likewise builds a
// re.escape-based `*`->`.*` / `?`->`.` regex).
//
// IAM action names are case-insensitive, so both sides are lower-cased before the
// (case-sensitive) regex — equivalent to the re.IGNORECASE the Python compiles.
func actionPatternMatches(pattern, action string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ":*") && strings.Contains(action, ":") {
		patternService := strings.ToLower(pattern[:strings.IndexByte(pattern, ':')])
		actionService := strings.ToLower(action[:strings.IndexByte(action, ':')])
		if patternService == actionService {
			return true
		}
	}
	if !strings.ContainsAny(pattern, "*?") {
		return strings.EqualFold(pattern, action)
	}
	return arnPatternRegex(strings.ToLower(pattern)).MatchString(strings.ToLower(action))
}

// anyActionMatches reports whether any of a statement's action patterns matches
// action. Mirrors the `any(_action_matches(a, action) for a in stmt_actions)`
// guard shared by the bucket-policy and Lambda resource-policy statement walks.
// A statement with no Action (nil/empty slice) matches nothing — matching
// `statement.get("Action", [])` defaulting to the empty list.
func anyActionMatches(actions []string, action string) bool {
	for _, a := range actions {
		if actionPatternMatches(a, action) {
			return true
		}
	}
	return false
}

// principalBlockMatches reports whether a resource-policy Principal (or
// NotPrincipal) block names principalArn. Ported from _helpers.principal_matches.
//
// The Python function takes an account_id argument that it documents as unused
// (account matching is derived from principalArn itself); it is omitted here.
//
// Branch order matches the Python exactly: a "*" block matches anyone; a service
// principal (a "…​.amazonaws.com" principalArn) matches only against Service
// entries; every other principal matches against AWS entries, where a bare
// 12-digit account matches only when it equals the principal's account, a
// "…:root" ARN matches every principal in that account (and never falls through
// to a pattern match), and anything else is an ARN pattern. This "…:root" control
// flow differs from TrustPrincipalMatches (see trust.go) — do not merge them.
func principalBlockMatches(p *Principal, principalArn string) bool {
	if p == nil {
		return false
	}
	if p.Wildcard {
		return true
	}

	principalAccount, _ := accountSegment(principalArn)

	if isServicePrincipalARN(principalArn) {
		// Service principal: match against Service entries (exact membership).
		for _, s := range p.Service {
			if s == principalArn {
				return true
			}
		}
		return false
	}

	for _, entry := range p.AWS {
		if entry == "*" {
			return true
		}
		// Bare 12-digit account ID: matches only its own account.
		if isTwelveDigitAccount(entry) {
			if principalAccount == entry {
				return true
			}
			continue
		}
		// Account root ARN: matches every principal in that account, and never
		// falls through to a pattern match.
		if strings.HasSuffix(entry, ":root") {
			parts := strings.Split(entry, ":")
			if len(parts) >= 5 && principalAccount != "" {
				if parts[4] == principalAccount {
					return true
				}
			}
			continue
		}
		if resourceMatches(entry, principalArn) {
			return true
		}
	}
	return false
}

// accountSegment returns the account field (index 4) of a colon-split ARN and
// whether it was present. Mirrors the raw `principal_arn.split(":")[4]`
// extraction used inside the principal/trust matchers — no 12-digit validation,
// so a malformed account (e.g. "") is returned as-is with ok=true. Distinct from
// accountIDFromARN, which validates.
func accountSegment(arn string) (string, bool) {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4], true
	}
	return "", false
}

// accountIDFromARN extracts and validates a 12-digit AWS account ID from an ARN.
// Ported from _helpers.extract_account_id: the account segment must be exactly 12
// digits, which rejects non-account partitions (e.g. the "aws" in
// arn:aws:iam::aws:policy/…). Used for the cross-account determinations, not for
// principal matching.
func accountIDFromARN(arn string) (string, bool) {
	if arn == "" || !strings.Contains(arn, ":") {
		return "", false
	}
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		account := parts[4]
		if isTwelveDigitAccount(account) {
			return account, true
		}
	}
	return "", false
}

// isTwelveDigitAccount reports whether s is exactly 12 ASCII digits. Mirrors the
// `entry.isdigit() and len(entry) == 12` account-id test (IAM entries are ASCII,
// so ASCII-digit checking matches str.isdigit here).
func isTwelveDigitAccount(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isServicePrincipalARN reports whether a principal string is an AWS service
// principal. Ported from _helpers._is_service_principal.
func isServicePrincipalARN(principal string) bool {
	return strings.HasSuffix(principal, ".amazonaws.com")
}
