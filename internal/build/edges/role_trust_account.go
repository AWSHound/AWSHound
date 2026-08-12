// This file ports the per-account processors of the role_trust_and_federation
// family (core/graph/edges/role_trust_and_federation/): roleTrustAccountEdges and
// the intra-account helpers for session/federation tokens, role and SAML/OIDC
// provider lifecycle, federated (SAML / Web Identity) role assumption, the
// create-provider-and-assume composites, and CanCreateAndAssumeAdminRole. The
// cross-account CanAssumeRole / HasExternalRoleTrust processors, the RoleTrustEdges
// entry point, the package's constituent-escalation descriptions, and the shared
// trust-parsing helpers all live in role_trust.go.
package edges

import (
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// roleTrustImmutable reports whether a role's trust policy cannot be rewritten via
// iam:UpdateAssumeRolePolicy, so the role is never a valid trust-rewrite target (and
// no CanUpdateAssumeRolePolicy-derived edge should point at it).
//
// This covers service-linked roles (path aws-service-role/): AWS rejects
// iam:UpdateAssumeRolePolicy on them — they are service-owned protected resources
// whose trust policy is immutable. Per the IAM User Guide, "You cannot modify the
// trust policy for a service-linked role"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_update-role-trust-policy.html).
//
// This is a static ARN-path check, not a permission check: even a principal whose
// IAM policy nominally allows iam:UpdateAssumeRolePolicy on * cannot actually rewrite
// a service-linked role's trust, so the edge would be a false positive.
//
// Note: IAM Identity Center reserved roles (aws-reserved/sso.amazonaws.com/) are NOT
// excluded — they are ordinary roles whose trust is technically modifiable (Identity
// Center merely reconciles it), and no AWS documentation denies the call on them.
func roleTrustImmutable(roleArn string) bool {
	return strings.Contains(roleArn, ":role/aws-service-role/")
}

// Composite-escalation descriptions, copied verbatim from the Python processors
// so the emitted `description` property is byte-identical.
const (
	roleTrustSAMLCreateAssumeDesc = "Principal can create a malicious SAML identity provider and rewrite a role's trust policy to trust it, " +
		"then assume the role via sts:AssumeRoleWithSAML using assertions from the attacker-controlled provider."
	roleTrustOIDCCreateAssumeDesc = "Principal can create a malicious OIDC identity provider and rewrite a role's trust policy to trust it, " +
		"then assume the role via sts:AssumeRoleWithWebIdentity using tokens from the attacker-controlled provider."
)

// -------------------------------------------------------------------------
// Per-account processors
// -------------------------------------------------------------------------

func roleTrustAccountEdges(pe *eval.PolicyEvaluator, acct *store.Account) []*graph.Edge {
	accountID := acct.ID
	root := accountRootARN(accountID)
	principals := principalARNs(acct)
	users := sortedKeys(acct.Users)
	roleARNs := sortedKeys(acct.Roles)
	samlARNs := sortedKeys(acct.SAMLProviders)
	oidcARNs := sortedKeys(acct.OIDCProviders)

	roleWildcard := "arn:aws:iam::" + accountID + ":role/*"

	var out []*graph.Edge

	// CanGetSessionToken: self-edge for any principal (users + roles) with
	// sts:GetSessionToken on "*".
	for _, p := range principals {
		res := pe.CanPerformAction(p, "sts:GetSessionToken", "*", nil)
		if res.Allowed {
			out = append(out, permissionEdge(p, p, graph.KindCanGetSessionToken, false, res))
		}
	}

	// CanGetFederationToken: self-edge for USERS only (roles cannot call it),
	// resource arn:aws:sts::{account}:federated-user/*.
	fedResource := "arn:aws:sts::" + accountID + ":federated-user/*"
	for _, u := range users {
		res := pe.CanPerformAction(u, "sts:GetFederationToken", fedResource, nil)
		if res.Allowed {
			out = append(out, permissionEdge(u, u, graph.KindCanGetFederationToken, false, res))
		}
	}

	// CanCreateRole: principal -> account root, resource role/*. Results are
	// captured for the create-and-assume / create-and-pass admin composites.
	createRoleRes := map[string]*eval.PermissionCheckResult{}
	for _, p := range principals {
		res := pe.CanPerformAction(p, "iam:CreateRole", roleWildcard, nil)
		if res.Allowed {
			createRoleRes[p] = res
			out = append(out, permissionEdge(p, root, graph.KindCanCreateRole, false, res))
		}
	}

	// Wildcard attach/put on role/* — cross-family base edges (iam_manipulation
	// emits them). Recomputed here for the admin composites but NOT emitted.
	attachWild := map[string]*eval.PermissionCheckResult{}
	putWild := map[string]*eval.PermissionCheckResult{}
	for _, p := range principals {
		if r := pe.CanPerformAction(p, "iam:AttachRolePolicy", roleWildcard, nil); r.Allowed {
			attachWild[p] = r
		}
		if r := pe.CanPerformAction(p, "iam:PutRolePolicy", roleWildcard, nil); r.Allowed {
			putWild[p] = r
		}
	}

	// CanDeleteRole: principal -> role.
	out = append(out, roleTrustActionEdges(pe, principals, "iam:DeleteRole", graph.KindCanDeleteRole, false, roleARNs)...)

	// CanUpdateAssumeRolePolicy (+ ...AndAssume). Capture allowed update results
	// per (principal, role) for the create-and-assume composites and the
	// PassRole trust-rewrite fallback in role_trust_meta.go.
	updateArp := map[string]map[string]*eval.PermissionCheckResult{}
	for _, p := range principals {
		for _, r := range roleARNs {
			// Service-linked and Identity Center reserved roles have immutable /
			// managed trust policies, so no iam:UpdateAssumeRolePolicy-derived edge
			// (base, ...AndAssume, the create-provider-and-assume composites, or the
			// PassRole trust-rewrite fallback) is a real target for them.
			if roleTrustImmutable(r) {
				continue
			}
			ures := pe.CanPerformAction(p, "iam:UpdateAssumeRolePolicy", r, nil)
			if !ures.Allowed {
				continue
			}
			out = append(out, permissionEdge(p, r, graph.KindCanUpdateAssumeRolePolicy, false, ures))
			if updateArp[p] == nil {
				updateArp[p] = map[string]*eval.PermissionCheckResult{}
			}
			updateArp[p][r] = ures
			// Composite: principal can also assume the role (IAM side only — the
			// attacker rewrites the trust policy first, so no trust check here).
			// Properties carry the UPDATE grant's sources/conditions.
			if ares := pe.CanPerformAction(p, "sts:AssumeRole", r, nil); ares.Allowed {
				e := graph.NewEdge(p, r, graph.KindCanUpdateAssumeRolePolicyAndAssume)
				e.Set("is_traversable", true)
				e.Set("allow_sources", roleTrustJoin(ures.AllowSources))
				e.Set("conditions", conditionsJSON(ures.Conditions))
				out = append(out, e)
			}
		}
	}

	// SAML provider management.
	samlResource := "arn:aws:iam::" + accountID + ":saml-provider/*"
	createSamlRes := map[string]*eval.PermissionCheckResult{}
	for _, p := range principals {
		res := pe.CanPerformAction(p, "iam:CreateSAMLProvider", samlResource, nil)
		if res.Allowed {
			createSamlRes[p] = res
			out = append(out, permissionEdge(p, root, graph.KindCanCreateSAMLProvider, false, res))
		}
	}
	out = append(out, roleTrustCreateProviderAndAssume(pe, principals, roleARNs, createSamlRes, updateArp,
		graph.KindCanCreateSAMLProviderAndAssumeRole, roleTrustSAMLCreateAssumeDesc)...)
	out = append(out, roleTrustActionEdges(pe, principals, "iam:UpdateSAMLProvider", graph.KindCanUpdateSAMLProvider, true, samlARNs)...)
	out = append(out, roleTrustActionEdges(pe, principals, "iam:DeleteSAMLProvider", graph.KindCanDeleteSAMLProvider, false, samlARNs)...)

	// OIDC provider management.
	oidcResource := "arn:aws:iam::" + accountID + ":oidc-provider/*"
	createOidcRes := map[string]*eval.PermissionCheckResult{}
	for _, p := range principals {
		res := pe.CanPerformAction(p, "iam:CreateOpenIDConnectProvider", oidcResource, nil)
		if res.Allowed {
			createOidcRes[p] = res
			out = append(out, permissionEdge(p, root, graph.KindCanCreateOIDCProvider, false, res))
		}
	}
	out = append(out, roleTrustCreateProviderAndAssume(pe, principals, roleARNs, createOidcRes, updateArp,
		graph.KindCanCreateOIDCProviderAndAssumeRole, roleTrustOIDCCreateAssumeDesc)...)
	out = append(out, roleTrustActionEdges(pe, principals, "iam:DeleteOpenIDConnectProvider", graph.KindCanDeleteOIDCProvider, false, oidcARNs)...)
	out = append(out, roleTrustActionEdges(pe, principals, "iam:AddClientIDToOpenIDConnectProvider", graph.KindCanAddClientIDToOIDCProvider, false, oidcARNs)...)
	out = append(out, roleTrustActionEdges(pe, principals, "iam:RemoveClientIDFromOpenIDConnectProvider", graph.KindCanRemoveClientIDFromOIDCProvider, false, oidcARNs)...)
	out = append(out, roleTrustActionEdges(pe, principals, "iam:UpdateOpenIDConnectProviderThumbprint", graph.KindCanUpdateOIDCProviderThumbprint, true, oidcARNs)...)

	// Federated role assumption (SAML / Web Identity): provider -> role, gated
	// only by the role's Principal.Federated trust (no IAM check). Roles are
	// same-account. Parse each role's trust doc once.
	docByRole := make(map[string]*eval.Policy, len(roleARNs))
	for _, r := range roleARNs {
		docByRole[r] = roleTrustParseTrust(acct.Roles[r])
	}
	out = append(out, roleTrustFederatedAssume(samlARNs, roleARNs, docByRole, "sts:AssumeRoleWithSAML", graph.KindCanAssumeRoleWithSAML)...)
	out = append(out, roleTrustFederatedAssume(oidcARNs, roleARNs, docByRole, "sts:AssumeRoleWithWebIdentity", graph.KindCanAssumeRoleWithWebIdentity)...)

	// CanCreateAndAssumeAdminRole: create a role, attach admin, assume it — needs
	// no service and no iam:PassRole. Candidate = create-role ∩ (attach|put)
	// wildcard, gated on sts:AssumeRole on role/*.
	out = append(out, roleTrustCreateAndAssumeAdminRole(pe, accountID, principals, createRoleRes, attachWild, putWild)...)

	// Meta merges (role_trust_meta.go).
	out = append(out, roleTrustPassRoleToServiceEdges(pe, acct, roleARNs, principals, updateArp)...)
	out = append(out, roleTrustCreateAndPassAdminRoleEdges(pe, acct, principals, createRoleRes, attachWild, putWild)...)

	return out
}

// roleTrustCreateProviderAndAssume ports the CanCreate{SAML,OIDC}ProviderAndAssumeRole
// composites: a principal that can create a federation provider AND rewrite a
// role's trust policy can assume that role via the attacker-controlled provider.
// One traversable edge per (create-capable principal, role) pair the principal
// can iam:UpdateAssumeRolePolicy (excluding self). Properties carry the update
// grant's sources and both grants' conditions.
func roleTrustCreateProviderAndAssume(
	pe *eval.PolicyEvaluator,
	principals, roleARNs []string,
	createRes map[string]*eval.PermissionCheckResult,
	updateArp map[string]map[string]*eval.PermissionCheckResult,
	kind graph.EdgeKind,
	description string,
) []*graph.Edge {
	var out []*graph.Edge
	for _, p := range principals {
		cres, ok := createRes[p]
		if !ok {
			continue
		}
		perPrincipal := updateArp[p]
		if perPrincipal == nil {
			continue
		}
		for _, r := range roleARNs {
			if p == r {
				continue
			}
			ures, ok := perPrincipal[r]
			if !ok {
				continue
			}
			e := graph.NewEdge(p, r, kind)
			e.Set("is_traversable", true)
			e.Set("description", description)
			e.Set("allow_sources", roleTrustJoin(ures.AllowSources))
			e.Set("update_trust_conditions", conditionsJSON(ures.Conditions))
			e.Set("create_provider_conditions", conditionsJSON(cres.Conditions))
			out = append(out, e)
		}
	}
	return out
}

// roleTrustFederatedAssume ports CanAssumeRoleWith{SAML,WebIdentity}: an edge
// provider->role for every role whose trust policy admits the federation
// provider for action (no IAM check — only Principal.Federated is evaluated).
func roleTrustFederatedAssume(providerARNs, roleARNs []string, docByRole map[string]*eval.Policy, action string, kind graph.EdgeKind) []*graph.Edge {
	var out []*graph.Edge
	for _, provArn := range providerARNs {
		for _, rArn := range roleARNs {
			doc := docByRole[rArn]
			if doc == nil {
				continue
			}
			tr := eval.EvaluateFederatedTrust(doc, provArn, action, nil)
			if !tr.Trusted {
				continue
			}
			e := graph.NewEdge(provArn, rArn, kind)
			e.Set("is_traversable", true)
			e.Set("trust_policy_conditions", conditionsJSON(tr.Conditions))
			out = append(out, e)
		}
	}
	return out
}

// roleTrustCreateAndAssumeAdminRole ports CanCreateAndAssumeAdminRoleEdgeProcessor.
// A principal who can iam:CreateRole, attach an admin-grade policy to role/*
// (AttachRolePolicy or PutRolePolicy), and sts:AssumeRole role/* can create a
// role trusting itself, attach AdministratorAccess, and assume it — account
// takeover. The role does not exist yet, so the trust side is satisfied by
// construction and not checked. One traversable edge per principal -> account
// root.
func roleTrustCreateAndAssumeAdminRole(
	pe *eval.PolicyEvaluator,
	accountID string,
	principals []string,
	createRoleRes, attachWild, putWild map[string]*eval.PermissionCheckResult,
) []*graph.Edge {
	root := accountRootARN(accountID)
	roleWildcard := "arn:aws:iam::" + accountID + ":role/*"

	var out []*graph.Edge
	for _, p := range principals {
		cr, ok := createRoleRes[p]
		if !ok {
			continue
		}
		attachRes, attachMethod := roleTrustPickAttach(attachWild, putWild, p)
		if attachRes == nil {
			continue
		}
		assume := pe.CanPerformAction(p, "sts:AssumeRole", roleWildcard, nil)
		if !assume.Allowed {
			continue
		}
		// Aggregate conditions across create-role, assume, and attach (in that
		// order; concatenated, not deduped — matches the Python).
		var conds []map[string]any
		conds = append(conds, cr.Conditions...)
		conds = append(conds, assume.Conditions...)
		conds = append(conds, attachRes.Conditions...)

		e := graph.NewEdge(p, root, graph.KindCanCreateAndAssumeAdminRole)
		e.Set("is_traversable", true)
		e.Set("create_role_allow_sources", roleTrustJoin(cr.AllowSources))
		e.Set("attach_policy_allow_sources", roleTrustJoin(attachRes.AllowSources))
		e.Set("attach_policy_method", attachMethod)
		e.Set("assume_role_allow_sources", roleTrustJoin(assume.AllowSources))
		e.Set("conditions", conditionsJSON(conds))
		out = append(out, e)
	}
	return out
}
