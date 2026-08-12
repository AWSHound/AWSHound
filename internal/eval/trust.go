package eval

import (
	"strconv"
	"strings"
)

// This file ports AWSHound's role trust-policy evaluation:
//
//   - core/evaluation/trust_policy.py    -> TrustPrincipalMatches,
//                                            TrustFederatedMatches (the pure
//                                            Principal-block matchers)
//   - core/evaluation/trust_evaluator.py -> evaluateTrustDoc (evaluate_trust_doc),
//                                            the single trust-document walker
//   - check_federated_trust_policy       -> EvaluateFederatedTrust
//
// The sts:AssumeRole wrapper (check_trust_policy) is PolicyEvaluator.CheckTrustPolicy
// in evaluator.go: it is bitmap-accelerated, then parses the AssumeRolePolicyDocument
// and calls evaluateTrustDoc with TrustPrincipalMatches.
//
// A trust policy decides whether a role admits a candidate — an IAM/account
// principal (sts:AssumeRole) or a federated SAML/OIDC provider
// (sts:AssumeRoleWithSAML / sts:AssumeRoleWithWebIdentity). Condition resolution
// routes through the shared ResolveMatchedStatements arbiter, so the tri-state
// attacker-bias rule cannot drift from the identity and resource-policy paths.

// TrustMatchFn matches a statement's Principal block against a candidate target
// ARN. Ported from trust_evaluator.TrustMatchFn. The two implementations are
// TrustPrincipalMatches (IAM principals, Principal.AWS) and TrustFederatedMatches
// (federation providers, Principal.Federated).
type TrustMatchFn func(p *Principal, targetArn string) bool

// TrustPrincipalMatches reports whether a trust-policy Principal block trusts the
// IAM principalArn. Ported from trust_policy.trust_principal_matches; this is the
// single canonical AWS-principal trust matcher — CheckTrustPolicy (via
// evaluateTrustDoc) is its one caller, and this logic is what the live suite
// validates.
//
// It inspects only Principal.AWS ("*" trusts everyone; a bare 12-digit account is
// normalised to its :root ARN; a :root ARN trusts every principal in that
// account; anything else is an ARN pattern). Principal.Service and
// Principal.Federated are ignored here — they have their own checks.
//
// Its :root control flow differs subtly from principalBlockMatches (resource.go):
// here a bare 12-digit entry is first rewritten to a :root ARN, and a :root entry
// on a principal with no resolvable account (empty account segment) falls through
// to an ARN pattern match rather than being skipped. Keep the two matchers separate.
func TrustPrincipalMatches(p *Principal, principalArn string) bool {
	if p == nil {
		return false
	}
	if p.Wildcard {
		return true
	}
	principalAccount := ""
	if c := strings.Split(principalArn, ":"); len(c) >= 5 {
		principalAccount = c[4]
	}
	for _, entry := range p.AWS {
		if entry == "*" {
			return true
		}
		e := entry
		// Bare 12-digit account IDs -> root ARN.
		if isDigits(e) && len(e) == 12 {
			e = "arn:aws:iam::" + e + ":root"
		}
		// Account root matches every principal in that account.
		if strings.HasSuffix(e, ":root") {
			parts := strings.Split(e, ":")
			if len(parts) >= 5 && principalAccount != "" {
				if parts[4] == principalAccount {
					return true
				}
				continue
			}
		}
		if resourceMatches(e, principalArn) {
			return true
		}
	}
	return false
}

// TrustFederatedMatches reports whether a trust-policy Principal block trusts the
// federated providerArn. Ported from trust_policy.trust_federated_matches: it
// inspects only Principal.Federated ("*" trusts everyone; any entry that is "*"
// or ARN-glob-matches the provider trusts it). Other Principal keys are ignored.
func TrustFederatedMatches(p *Principal, providerArn string) bool {
	if p == nil {
		return false
	}
	if p.Wildcard {
		return true
	}
	for _, entry := range p.Federated {
		if entry == "*" {
			return true
		}
		if resourceMatches(entry, providerArn) {
			return true
		}
	}
	return false
}

// EvaluateFederatedTrust checks whether a role's trust policy admits the
// federated providerArn (a SAML or OIDC provider) for action (e.g.
// sts:AssumeRoleWithSAML / sts:AssumeRoleWithWebIdentity). It is
// check_federated_trust_policy specialised to the federated matcher.
//
// doc is the parsed trust policy — parse RoleDetail.AssumeRolePolicyDocument via
// ParsePolicyDocument (trust documents ARE url-encoded). A nil doc is not trusted.
// ctxFactory lazily builds the RequestContext for condition resolution (invoked
// only when a matched statement is conditioned); a nil factory yields a blank
// context, under which an unresolved condition is retained as a conditional trust
// (attacker bias).
func EvaluateFederatedTrust(doc *Policy, providerArn, action string, ctxFactory ContextFactory) TrustCheckResult {
	return evaluateTrustDoc(doc, providerArn, action, TrustFederatedMatches, ctxFactory)
}

// evaluateTrustDoc evaluates a parsed trust policy against a candidate. Ported
// from trust_evaluator.evaluate_trust_doc.
//
// Allow and Deny statements are arbitrated together, so a matching trust-policy
// Deny suppresses an Allow. Principal and NotPrincipal blocks are both honored.
func evaluateTrustDoc(doc *Policy, targetArn, action string, matchFn TrustMatchFn, ctxFactory ContextFactory) TrustCheckResult {
	statementMatches := func(st *Statement, target string) bool {
		return trustStatementPrincipalMatches(st, target, matchFn)
	}
	return evaluateTrustDocWithMatchers(doc, targetArn, action, statementMatches, statementMatches, ctxFactory)
}

type trustStatementMatchFn func(*Statement, string) bool

func evaluateTrustDocWithMatchers(doc *Policy, targetArn, action string, allowMatch, denyMatch trustStatementMatchFn, ctxFactory ContextFactory) TrustCheckResult {
	if doc == nil {
		return TrustCheckResult{Trusted: false}
	}
	actionLower := strings.ToLower(action)
	var matchedAllows []MatchedStatement
	var matchedDenies []MatchedStatement
	for idx := range doc.Statements {
		st := &doc.Statements[idx]
		if !trustStatementActionMatches(st, actionLower) {
			continue
		}
		matched := MatchedStatement{Condition: st.Condition, Source: "trust/" + strconv.Itoa(idx)}
		switch Effect(st.Effect) {
		case EffectAllow:
			if allowMatch(st, targetArn) {
				matchedAllows = append(matchedAllows, matched)
			}
		case EffectDeny:
			if denyMatch(st, targetArn) {
				matchedDenies = append(matchedDenies, matched)
			}
		}
	}
	if len(matchedAllows) == 0 && len(matchedDenies) == 0 {
		return TrustCheckResult{Trusted: false}
	}
	resolution := ResolveMatchedStatements(matchedAllows, matchedDenies, ctxFactory)
	return TrustCheckResult{
		Trusted:    resolution.Allowed,
		Conditions: resolution.Conditions,
	}
}

func trustStatementPrincipalMatches(st *Statement, target string, matchFn TrustMatchFn) bool {
	if st.Principal != nil {
		return matchFn(st.Principal, target)
	}
	if st.NotPrincipal != nil {
		return !matchFn(st.NotPrincipal, target)
	}
	return false
}

// trustActionMatches reports whether any policy action, lower-cased, is exactly
// the requested (already lower-cased) action, "sts:*", or "*". Mirrors the
// `any(a.lower() in (action_lower, "sts:*", "*") …)` guard in evaluate_trust_doc —
// exact membership, not a glob.
func trustActionMatches(actions []string, actionLower string) bool {
	for _, a := range actions {
		al := strings.ToLower(a)
		if al == actionLower || al == "sts:*" || al == "*" {
			return true
		}
	}
	return false
}

func trustStatementActionMatches(statement *Statement, actionLower string) bool {
	if statement.Action != nil {
		return trustActionMatches(statement.Action, actionLower)
	}
	if statement.NotAction != nil {
		return !trustActionMatches(statement.NotAction, actionLower)
	}
	return false
}
