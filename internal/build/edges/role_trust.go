// This file ports the role_trust_and_federation family
// (core/graph/edges/role_trust_and_federation/): the STS / role-assumption /
// federation / PassRole attack paths.
//
// Directly-ported processors (self-contained, gated purely by the policy
// evaluator + the store's trust documents):
//
//	CanAssumeRole                      AWS_CanAssumeRole              (traversable)
//	  + HasExternalRoleTrust           AWS_HasExternalRoleTrust
//	CanAssumeRoleWithSAML              AWS_CanAssumeRoleWithSAML       (traversable)
//	CanAssumeRoleWithWebIdentity       AWS_CanAssumeRoleWithWebIdentity(traversable)
//	CanGetFederationToken              AWS_CanGetFederationToken
//	CanGetSessionToken                 AWS_CanGetSessionToken
//	CanUpdateAssumeRolePolicy          AWS_CanUpdateAssumeRolePolicy
//	  + ...AndAssume                   AWS_CanUpdateAssumeRolePolicyAndAssume (traversable)
//	CanCreateRole                      AWS_CanCreateRole
//	CanDeleteRole                      AWS_CanDeleteRole
//	CanCreateSAMLProvider              AWS_CanCreateSAMLProvider
//	CanCreateSAMLProviderAndAssumeRole AWS_CanCreateSAMLProviderAndAssumeRole (traversable)
//	CanUpdateSAMLProvider              AWS_CanUpdateSAMLProvider        (traversable)
//	CanDeleteSAMLProvider              AWS_CanDeleteSAMLProvider
//	CanCreateOIDCProvider              AWS_CanCreateOIDCProvider
//	CanCreateOIDCProviderAndAssumeRole AWS_CanCreateOIDCProviderAndAssumeRole (traversable)
//	CanDeleteOIDCProvider              AWS_CanDeleteOIDCProvider
//	CanAddClientIDToOIDCProvider       AWS_CanAddClientIDToOIDCProvider
//	CanRemoveClientIDFromOIDCProvider  AWS_CanRemoveClientIDFromOIDCProvider
//	CanUpdateOIDCProviderThumbprint    AWS_CanUpdateOIDCProviderThumbprint (traversable)
//	CanCreateAndAssumeAdminRole        AWS_CanCreateAndAssumeAdminRole  (traversable)
//
// The two merge/meta processors — CanPassRoleToService and
// CanCreateAndPassAdminRole — live in role_trust_meta.go and are invoked per
// account from roleTrustAccountEdges.
//
// Fidelity notes:
//   - Candidate principals are users + roles only (Python's
//     get_all_principal_arns excludes groups); groups only ever appear as
//     targets of an edge, never as a source here.
//   - CanAssumeRole is the one cross-account processor: it iterates EVERY role in
//     the store (a principal may assume a role in another account) intersected
//     with the global set of principals holding sts:AssumeRole, exactly the
//     trust-bitmap ∩ iam-bitmap the Python runs per account and unions.
//   - CanCreateAndAssumeAdminRole consumes the CanAttachRolePolicyWildcard /
//     CanPutRolePolicyWildcard base edges the iam_manipulation family emits; they
//     are recomputed here with the exact gating of their own processors but are
//     NOT emitted (their family emits them), following the iam_manipulation
//     precedent for cross-family composites.
package edges

import (
	"regexp"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// RoleTrustEdges emits the role_trust_and_federation family's edges for every
// account in the store. CanAssumeRole and HasExternalRoleTrust are computed
// globally (they span accounts); every other processor is intra-account and runs
// per account in ascending id order so output is deterministic.
func RoleTrustEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	accts := s.Accounts()
	sort.Slice(accts, func(i, j int) bool { return accts[i].ID < accts[j].ID })

	var out []*graph.Edge
	out = append(out, roleTrustCanAssumeRoleEdges(s, pe)...)
	out = append(out, roleTrustHasExternalRoleTrustEdges(s)...)
	for _, acct := range accts {
		out = append(out, roleTrustAccountEdges(pe, acct)...)
	}
	return out
}

// -------------------------------------------------------------------------
// CanAssumeRole (cross-account) + HasExternalRoleTrust
// -------------------------------------------------------------------------

// roleTrustCanAssumeRoleEdges ports CanAssumeRoleEdgeProcessor's AWS_CanAssumeRole
// half. Cross-account and account-root delegation require BOTH an identity-policy
// sts:AssumeRole grant and trust. An exact same-account IAM user/role Principal ARN
// in the trust policy is itself a resource-based permission grant and needs no
// second identity-policy Allow; trust/identity denies, permissions boundaries,
// and organization guardrails still constrain the direct grant.
func roleTrustCanAssumeRoleEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	roles := roleTrustAllRoles(s)
	iamBM := pe.PrincipalsWithAction("sts:AssumeRole", "*")

	var out []*graph.Edge
	for _, role := range roles {
		trustBM := pe.RoleTrustBitmap(role, "sts:AssumeRole")
		identityCandidates := trustBM.Clone()
		identityCandidates.And(iamBM)
		directCandidates := pe.RoleDirectSameAccountTrustBitmap(role, "sts:AssumeRole")
		identityCandidates.Or(directCandidates)
		for _, pid := range identityCandidates.ToArray() {
			principalArn := s.ARN().Arn(pid)
			if principalArn == "" || principalArn == role.Arn {
				continue // skip missing index entries + self-assumption
			}
			// Resource-matched IAM check: confirm the sts:AssumeRole grant covers
			// THIS role, not just some role.
			res := pe.CanPerformAction(principalArn, "sts:AssumeRole", role.Arn, nil)
			directGrant := false
			tr := pe.CheckTrustPolicy(role, principalArn, nil)
			if tr == nil || !tr.Trusted {
				continue
			}
			if !res.Allowed {
				if !directCandidates.Contains(pid) {
					continue
				}
				direct := pe.CheckDirectSameAccountTrustPolicy(role, principalArn, nil)
				if direct == nil || !direct.Trusted {
					continue
				}
				constraints := pe.CheckDirectGrantConstraints(principalArn, "sts:AssumeRole", role.Arn, nil)
				if constraints == nil || !constraints.Allowed {
					continue
				}
				res = constraints
				tr = direct
				directGrant = true
			}
			e := graph.NewEdge(principalArn, role.Arn, graph.KindCanAssumeRole)
			e.Set("is_traversable", true)
			if directGrant {
				e.Set("allow_sources", "role trust policy (direct same-account principal)")
			} else {
				e.Set("allow_sources", roleTrustJoin(res.AllowSources))
			}
			e.Set("conditions", conditionsJSON(res.Conditions))
			e.Set("trust_policy_conditions", conditionsJSON(tr.Conditions))
			out = append(out, e)
		}
	}
	return out
}

// roleTrustHasExternalRoleTrustEdges ports CanAssumeRoleEdgeProcessor's
// AWS_HasExternalRoleTrust half: a non-traversable account-level fact
// source-root->target-root meaning "some role in source has a trust policy that
// permits account target to assume it". It is derived from the trust-policy
// *declaration* (not from a concrete assuming principal existing), so a wildcard
// account principal fans out to every known account. The target-account universe
// is the set of accounts in the store (the Python runs once per known account).
func roleTrustHasExternalRoleTrustEdges(s *store.Store) []*graph.Edge {
	var knownAccounts []string
	for _, a := range s.Accounts() {
		knownAccounts = append(knownAccounts, a.ID)
	}
	sort.Strings(knownAccounts)

	type pairKey struct{ src, tgt string }
	entriesByPair := map[pairKey]map[string]bool{}

	for _, role := range roleTrustAllRoles(s) {
		roleAcct := roleTrustAccountOf(role.Arn)
		if roleAcct == "" {
			continue
		}
		doc := roleTrustParseTrust(role)
		if doc == nil {
			continue
		}
		entries := roleTrustIterTrustPrincipalEntries(doc)
		if len(entries) == 0 {
			continue
		}
		for _, tgt := range knownAccounts {
			if tgt == roleAcct {
				continue // same-account trust is not external
			}
			trusted := false
			var roleEntries []string
			for _, entry := range entries {
				if roleTrustPrincipalEntryTrustsAccount(entry, tgt) {
					trusted = true
					if strings.Contains(entry, ":role/") {
						roleEntries = append(roleEntries, entry)
					}
				}
			}
			if !trusted {
				continue
			}
			pk := pairKey{roleAcct, tgt}
			set := entriesByPair[pk]
			if set == nil {
				set = map[string]bool{}
				entriesByPair[pk] = set
			}
			for _, re := range roleEntries {
				set[re] = true
			}
		}
	}

	pairs := make([]pairKey, 0, len(entriesByPair))
	for pk := range entriesByPair {
		pairs = append(pairs, pk)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].src != pairs[j].src {
			return pairs[i].src < pairs[j].src
		}
		return pairs[i].tgt < pairs[j].tgt
	})

	var out []*graph.Edge
	for _, pk := range pairs {
		e := graph.NewEdge(accountRootARN(pk.src), accountRootARN(pk.tgt), graph.KindHasExternalRoleTrust)
		e.Set("is_traversable", false)
		e.Set("trusted_roles", strings.Join(sortedKeys(entriesByPair[pk]), ", "))
		out = append(out, e)
	}
	return out
}

// -------------------------------------------------------------------------
// Shared helpers (prefixed roleTrust to avoid collisions with sibling families)
// -------------------------------------------------------------------------

// roleTrustActionEdges emits `principal -> target` base edges for every
// (principal, target) pair where the principal is allowed action on the target,
// carrying the standard (is_traversable, allow_sources, conditions) property
// triple. Ports the simple per-target BaseEdgeProcessor bodies.
func roleTrustActionEdges(pe *eval.PolicyEvaluator, principals []string, action string, kind graph.EdgeKind, traversable bool, targets []string) []*graph.Edge {
	if len(targets) == 0 {
		return nil
	}
	var out []*graph.Edge
	for _, p := range principals {
		for _, t := range targets {
			res := pe.CanPerformAction(p, action, t, nil)
			if res.Allowed {
				out = append(out, permissionEdge(p, t, kind, traversable, res))
			}
		}
	}
	return out
}

// roleTrustPickAttach returns the wildcard attach/put result for a principal,
// preferring AttachRolePolicy over PutRolePolicy (matching the Python's
// attach-first fallback), or (nil, "") when the principal has neither.
func roleTrustPickAttach(attachWild, putWild map[string]*eval.PermissionCheckResult, p string) (*eval.PermissionCheckResult, string) {
	if r, ok := attachWild[p]; ok {
		return r, "AttachRolePolicy"
	}
	if r, ok := putWild[p]; ok {
		return r, "PutRolePolicy"
	}
	return nil, ""
}

// roleTrustEvaluatePassRole ports edges/_pass_role.evaluate_pass_role: the
// iam:PassRole grant for (principal, role) evaluated with iam:PassedToService set
// to service, or nil when the principal cannot pass that role (a principal never
// passes itself). service scoping means a grant that restricts PassedToService to
// a different service is correctly denied for this path.
func roleTrustEvaluatePassRole(pe *eval.PolicyEvaluator, principal, role, service string) *eval.PermissionCheckResult {
	if principal == role {
		return nil
	}
	ctx := &eval.RequestContext{Values: map[string]string{"iam:passedtoservice": service}}
	res := pe.CanPerformAction(principal, "iam:PassRole", role, ctx)
	if !res.Allowed {
		return nil
	}
	return res
}

// roleTrustEvaluatePassRoleWildcard ports evaluate_pass_role_wildcard: PassRole
// against the account's role/* wildcard resource ("can pass any, incl.
// not-yet-created, role in the account").
func roleTrustEvaluatePassRoleWildcard(pe *eval.PolicyEvaluator, accountID, principal, service string) *eval.PermissionCheckResult {
	return roleTrustEvaluatePassRole(pe, principal, "arn:aws:iam::"+accountID+":role/*", service)
}

// roleTrustRolesTrustingService ports _service_trust_helpers.roles_trusting_service:
// the set of role ARNs in the account whose trust policy has an Allow statement
// naming service_principal (e.g. ec2.amazonaws.com) in Principal.Service (a bare
// "*" principal trusts every service).
func roleTrustRolesTrustingService(acct *store.Account, servicePrincipal string) map[string]bool {
	out := map[string]bool{}
	for arn, role := range acct.Roles {
		if roleTrustRoleTrustsService(role, servicePrincipal) {
			out[arn] = true
		}
	}
	return out
}

func roleTrustRoleTrustsService(role *model.RoleDetail, servicePrincipal string) bool {
	doc := roleTrustParseTrust(role)
	if doc == nil {
		return false
	}
	for i := range doc.Statements {
		st := &doc.Statements[i]
		if st.Effect != "Allow" {
			continue
		}
		block := st.Principal
		if block == nil {
			continue
		}
		if block.Wildcard {
			return true
		}
		for _, s := range block.Service {
			if s == servicePrincipal {
				return true
			}
		}
	}
	return false
}

// roleTrustIterTrustPrincipalEntries ports _iter_trust_principal_entries: every
// Principal.AWS entry from Allow statements that grant sts:AssumeRole (or sts:* /
// *), with a bare "*" principal surfaced as the literal "*". Service and
// Federated principals are excluded.
func roleTrustIterTrustPrincipalEntries(doc *eval.Policy) []string {
	var out []string
	for i := range doc.Statements {
		st := &doc.Statements[i]
		if st.Effect != "Allow" {
			continue
		}
		if !roleTrustHasAssumeAction(st.Action) {
			continue
		}
		block := st.Principal
		if block == nil {
			continue
		}
		if block.Wildcard {
			out = append(out, "*")
			continue
		}
		out = append(out, block.AWS...)
	}
	return out
}

// roleTrustHasAssumeAction reports whether any action, lower-cased, is one of
// sts:assumerole / sts:* / * (set membership, matching _ASSUME_ROLE_ACTIONS).
func roleTrustHasAssumeAction(actions []string) bool {
	for _, a := range actions {
		switch strings.ToLower(a) {
		case "sts:assumerole", "sts:*", "*":
			return true
		}
	}
	return false
}

// roleTrustPrincipalEntryTrustsAccount ports _principal_entry_trusts_account: a
// trust-policy Principal.AWS entry permits target when it is "*", a 12-digit
// account (or :root ARN) for target, or any ARN whose account field (index 4)
// equals target or wildcard-matches it.
func roleTrustPrincipalEntryTrustsAccount(entry, target string) bool {
	if entry == "*" {
		return true
	}
	if isTwelveDigit(entry) {
		entry = "arn:aws:iam::" + entry + ":root"
	}
	parts := strings.Split(entry, ":")
	if len(parts) < 5 {
		return false
	}
	field := parts[4]
	if field == target {
		return true
	}
	if strings.ContainsAny(field, "*?") {
		return roleTrustPatternMatches(field, target)
	}
	return false
}

// roleTrustPatternMatches ports trust_policy.arn_pattern_to_regex applied to a
// single ARN field: "*" -> ".*", "?" -> ".", everything else literal, anchored.
func roleTrustPatternMatches(pattern, s string) bool {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// roleTrustParseTrust parses a role's URL-encoded AssumeRolePolicyDocument,
// returning nil for an absent or unparseable document (matching the Python's
// `if not trust_doc` skips).
func roleTrustParseTrust(role *model.RoleDetail) *eval.Policy {
	if role == nil || role.AssumeRolePolicyDocument == "" {
		return nil
	}
	doc, err := eval.ParsePolicyDocument(role.AssumeRolePolicyDocument)
	if err != nil {
		return nil
	}
	return doc
}

// roleTrustAllRoles returns every role in the store, sorted by ARN.
func roleTrustAllRoles(s *store.Store) []*model.RoleDetail {
	var roles []*model.RoleDetail
	for _, a := range s.Accounts() {
		for _, r := range a.Roles {
			roles = append(roles, r)
		}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Arn < roles[j].Arn })
	return roles
}

// roleTrustJoin joins with ", " — the ", ".join(...) idiom.
func roleTrustJoin(vals []string) string { return strings.Join(vals, ", ") }

// roleTrustAccountOf returns the account-id segment (index 4) of an ARN, or "".
func roleTrustAccountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
