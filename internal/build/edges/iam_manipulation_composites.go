// This file ports the escalation composites of the iam_manipulation family
// (core/graph/edges/iam_manipulation/): CanUpdateSelfPolicy, CanUpdateOtherPolicy,
// and CanCreateAndAccessAdminUser, together with the composite-support helpers
// (attached custom-policy resolution, group-by-name lookup, permissions-boundary
// detection, and unique allow-source aggregation). The family entry point, the
// per-account dispatcher, the base-edge primitive emitters, and the package doc
// comment live in iam_manipulation.go.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// iamManipUpdateSelfPolicy ports CanUpdateSelfPolicyEdgeProcessor: a principal
// that can rewrite a permission container it is itself subject to (its own
// inline/attached user or role policy, or a customer-managed policy attached to
// it directly or via a group) escalates to admin with no assume step. One
// traversable edge per principal to the account root, gated by the principal
// having no capping permissions boundary.
func iamManipUpdateSelfPolicy(st *iamManipState, customSet map[string]bool) {
	acct := st.acct

	type contrib struct {
		method string
		check  iamManipCheck
	}
	per := map[string][]contrib{}
	add := func(principal, method string, c iamManipCheck) {
		per[principal] = append(per[principal], contrib{method, c})
	}

	// Self-referential policy writes (start == end): the principal can modify
	// its own policy. Method order mirrors _SELF_WRITE_METHODS.
	selfWrite := []struct {
		kind   graph.EdgeKind
		method string
	}{
		{graph.KindCanPutRolePolicy, "PutRolePolicy"},
		{graph.KindCanAttachRolePolicy, "AttachRolePolicy"},
		{graph.KindCanPutUserPolicy, "PutUserPolicy"},
		{graph.KindCanAttachUserPolicy, "AttachUserPolicy"},
	}
	for _, sw := range selfWrite {
		for _, c := range st.checks[sw.kind] {
			if c.start == c.end {
				add(c.start, sw.method, c)
			}
		}
	}

	// CreatePolicyVersion on a customer-managed policy attached to the actor.
	for _, c := range st.checks[graph.KindCanCreatePolicyVersion] {
		attached := iamManipAttachedCustomPolicies(acct, c.start, customSet)
		if attached[c.end] {
			add(c.start, "CreatePolicyVersion", c)
		}
	}

	principals := make([]string, 0, len(per))
	for p := range per {
		principals = append(principals, p)
	}
	sort.Strings(principals)

	for _, principal := range principals {
		// A capping permissions boundary means rewriting its own policy can't
		// exceed the boundary, so it doesn't actually yield admin.
		if iamManipHasBoundary(acct, principal) {
			continue
		}
		var sources []string
		var conds []map[string]any
		methodSet := map[string]bool{}
		for _, ct := range per[principal] {
			methodSet[ct.method] = true
			sources = iamManipAppendUnique(sources, ct.check.allowSrc)
			conds = append(conds, ct.check.conditions...)
		}
		methods := sortedKeys(methodSet)

		e := graph.NewEdge(principal, st.root, graph.KindCanUpdateSelfPolicy)
		e.Set("is_traversable", true)
		e.Set("methods", strings.Join(methods, ", "))
		e.Set("allow_sources", strings.Join(sources, ", "))
		e.Set("conditions", conditionsJSON(conds))
		st.emit(e)
	}
}

// iamManipUpdateOtherPolicy ports CanUpdateOtherPolicyEdgeProcessor: a source
// principal escalates through another principal it can both CONTROL (assume a
// role / mint a user's credentials) and RE-PERMISSION (rewrite its policy). One
// traversable edge per qualifying source to the account root, gated by the dest
// having no capping permissions boundary.
func iamManipUpdateOtherPolicy(st *iamManipState, customSet map[string]bool) {
	acct := st.acct

	control := iamManipControlPairs(st)

	repermission := map[iamManipPair][]iamManipCheck{}
	addReperm := func(src, dst string, c iamManipCheck) {
		if src == dst {
			return
		}
		pk := iamManipPair{src, dst}
		repermission[pk] = append(repermission[pk], c)
	}

	// Direct re-permission base edges (source -> dest principal), non-self.
	for _, kind := range []graph.EdgeKind{
		graph.KindCanPutRolePolicy, graph.KindCanAttachRolePolicy,
		graph.KindCanPutUserPolicy, graph.KindCanAttachUserPolicy,
	} {
		for _, c := range st.checks[kind] {
			if c.start != c.end {
				addReperm(c.start, c.end, c)
			}
		}
	}

	// CreatePolicyVersion re-permissions every principal the target policy is
	// attached to. Build policy -> attached-principals once.
	policyToPrincipals := map[string]map[string]bool{}
	for _, p := range principalARNs(acct) {
		for parn := range iamManipAttachedCustomPolicies(acct, p, customSet) {
			if policyToPrincipals[parn] == nil {
				policyToPrincipals[parn] = map[string]bool{}
			}
			policyToPrincipals[parn][p] = true
		}
	}
	for _, c := range st.checks[graph.KindCanCreatePolicyVersion] {
		for _, dst := range sortedKeys(policyToPrincipals[c.end]) {
			addReperm(c.start, dst, iamManipCheck{start: c.start, end: dst, allowSrc: c.allowSrc, conditions: c.conditions})
		}
	}

	// Qualifying pairs: source can BOTH control and re-permission the dest.
	var pairs []iamManipPair
	for pk := range control {
		if _, ok := repermission[pk]; ok {
			pairs = append(pairs, pk)
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].source != pairs[j].source {
			return pairs[i].source < pairs[j].source
		}
		return pairs[i].dest < pairs[j].dest
	})

	var order []string
	seen := map[string]bool{}
	srcSources := map[string][]string{}
	srcConds := map[string][]map[string]any{}
	for _, pk := range pairs {
		// A capping boundary on the dest means the re-permission can't grant it
		// admin.
		if iamManipHasBoundary(acct, pk.dest) {
			continue
		}
		if !seen[pk.source] {
			seen[pk.source] = true
			order = append(order, pk.source)
		}
		contribs := append(append([]iamManipCheck{}, control[pk]...), repermission[pk]...)
		for _, c := range contribs {
			srcSources[pk.source] = iamManipAppendUnique(srcSources[pk.source], c.allowSrc)
			srcConds[pk.source] = append(srcConds[pk.source], c.conditions...)
		}
	}

	for _, src := range order {
		e := graph.NewEdge(src, st.root, graph.KindCanUpdateOtherPolicy)
		e.Set("is_traversable", true)
		e.Set("allow_sources", strings.Join(srcSources[src], ", "))
		e.Set("conditions", conditionsJSON(srcConds[src]))
		st.emit(e)
	}
}

// iamManipControlPairs recomputes the cross-family "control" edges the
// CanUpdateOtherPolicy composite consumes — AssumeRole (dual IAM+trust check)
// and the credential-minting edges — scoped to the current account (the only
// pairs that can qualify, since the re-permission side is always same-account).
// These pairs are used internally and are NOT emitted (their own families emit
// them). Ports the gating of CanAssumeRoleEdgeProcessor and the
// Create/UpdateLoginProfile / CreateAccessKey SimpleActionEdgeProcessors.
func iamManipControlPairs(st *iamManipState) map[iamManipPair][]iamManipCheck {
	acct := st.acct
	control := map[iamManipPair][]iamManipCheck{}
	add := func(src, dst string, c iamManipCheck) {
		if src == dst {
			return
		}
		pk := iamManipPair{src, dst}
		control[pk] = append(control[pk], c)
	}

	// AssumeRole: source must have sts:AssumeRole on the dest role (IAM side) AND
	// the dest role's trust policy must permit source (trust side).
	assumeCands := filteredCandidates(acct, st.principalsWith("sts:AssumeRole"))
	for _, roleArn := range sortedKeys(acct.Roles) {
		role := acct.Roles[roleArn]
		for _, src := range assumeCands {
			if src == roleArn {
				continue
			}
			res := st.pe.CanPerformAction(src, "sts:AssumeRole", roleArn, nil)
			if !res.Allowed {
				continue
			}
			tr := st.pe.CheckTrustPolicy(role, src, nil)
			if tr == nil || !tr.Trusted {
				continue
			}
			add(src, roleArn, iamManipCheck{start: src, end: roleArn, allowSrc: res.AllowSources, conditions: res.Conditions})
		}
	}

	// Credential minting (dest = user): CreateAccessKey / CreateLoginProfile /
	// UpdateLoginProfile. Order mirrors _CONTROL_METHODS.
	users := sortedKeys(acct.Users)
	for _, action := range []string{"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"} {
		cands := filteredCandidates(acct, st.principalsWith(action))
		for _, src := range cands {
			for _, dstUser := range users {
				if src == dstUser {
					continue
				}
				res := st.pe.CanPerformAction(src, action, dstUser, nil)
				if !res.Allowed {
					continue
				}
				add(src, dstUser, iamManipCheck{start: src, end: dstUser, allowSrc: res.AllowSources, conditions: res.Conditions})
			}
		}
	}

	return control
}

// iamManipCreateAndAccessAdminUser ports CanCreateAndAccessAdminUserEdgeProcessor:
// a principal who can iam:CreateUser, grant the new user admin
// (Attach/PutUserPolicy on user/*), and mint credentials for it
// (CreateAccessKey/CreateLoginProfile on user/*) can take over the account. The
// user does not exist yet, so there is no boundary to check. One traversable
// edge per qualifying principal to the account root.
func iamManipCreateAndAccessAdminUser(st *iamManipState) {
	wildcardUser := "arn:aws:iam::" + st.acct.ID + ":user/*"

	grantActions := []struct{ action, method string }{
		{"iam:AttachUserPolicy", "AttachUserPolicy"},
		{"iam:PutUserPolicy", "PutUserPolicy"},
	}
	credActions := []struct{ action, method string }{
		{"iam:CreateAccessKey", "CreateAccessKey"},
		{"iam:CreateLoginProfile", "CreateLoginProfile"},
	}

	byPrincipal := map[string]iamManipCheck{}
	for _, c := range st.checks[graph.KindCanCreateUser] {
		byPrincipal[c.start] = c
	}
	principals := make([]string, 0, len(byPrincipal))
	for p := range byPrincipal {
		principals = append(principals, p)
	}
	sort.Strings(principals)

	for _, principal := range principals {
		createChk := byPrincipal[principal]

		var grantMethod string
		var grantRes *eval.PermissionCheckResult
		for _, g := range grantActions {
			if r := st.pe.CanPerformAction(principal, g.action, wildcardUser, nil); r.Allowed {
				grantMethod, grantRes = g.method, r
				break
			}
		}
		if grantRes == nil {
			continue
		}

		var credMethod string
		var credRes *eval.PermissionCheckResult
		for _, cr := range credActions {
			if r := st.pe.CanPerformAction(principal, cr.action, wildcardUser, nil); r.Allowed {
				credMethod, credRes = cr.method, r
				break
			}
		}
		if credRes == nil {
			continue
		}

		var allConds []map[string]any
		allConds = append(allConds, createChk.conditions...)
		allConds = append(allConds, grantRes.Conditions...)
		allConds = append(allConds, credRes.Conditions...)

		e := graph.NewEdge(principal, st.root, graph.KindCanCreateAndAccessAdminUser)
		e.Set("is_traversable", true)
		e.Set("methods", grantMethod+", "+credMethod)
		e.Set("create_user_allow_sources", strings.Join(createChk.allowSrc, ", "))
		e.Set("grant_allow_sources", strings.Join(grantRes.AllowSources, ", "))
		e.Set("credential_allow_sources", strings.Join(credRes.AllowSources, ", "))
		e.Set("conditions", conditionsJSON(allConds))
		st.emit(e)
	}
}

// ---------------------------------------------------------------------------
// Composite-support helpers
// ---------------------------------------------------------------------------

// iamManipAttachedCustomPolicies returns the customer-managed policy ARNs
// attached to principalArn — directly, and (for users) via each group it
// belongs to. Mirrors get_attached_custom_managed_policy_arns_for_principal.
func iamManipAttachedCustomPolicies(acct *store.Account, principalArn string, customSet map[string]bool) map[string]bool {
	out := map[string]bool{}
	collect := func(attached []model.AttachedPolicy) {
		for _, ap := range attached {
			if customSet[ap.PolicyArn] {
				out[ap.PolicyArn] = true
			}
		}
	}
	if u, ok := acct.Users[principalArn]; ok {
		collect(u.AttachedManagedPols)
		for _, gname := range u.GroupList {
			if g := iamManipGroupByName(acct, gname); g != nil {
				collect(g.AttachedManagedPols)
			}
		}
		return out
	}
	if r, ok := acct.Roles[principalArn]; ok {
		collect(r.AttachedManagedPols)
		return out
	}
	if g, ok := acct.Groups[principalArn]; ok {
		collect(g.AttachedManagedPols)
	}
	return out
}

// iamManipGroupByName returns the account's group whose GroupName matches, or
// nil. Mirrors _get_group_object (match by GroupName, not ARN).
func iamManipGroupByName(acct *store.Account, name string) *model.GroupDetail {
	for _, arn := range sortedKeys(acct.Groups) {
		if g := acct.Groups[arn]; g.GroupName == name {
			return g
		}
	}
	return nil
}

// iamManipHasBoundary reports whether a user or role principal has any
// permissions boundary attached. Mirrors
// _properties_helpers.principal_has_permissions_boundary (conservative: any
// attached boundary excludes the principal from admin-escalation claims).
func iamManipHasBoundary(acct *store.Account, arn string) bool {
	if u, ok := acct.Users[arn]; ok {
		return u.PermissionsBoundary != nil && u.PermissionsBoundary.PermissionsBoundaryArn != ""
	}
	if r, ok := acct.Roles[arn]; ok {
		return r.PermissionsBoundary != nil && r.PermissionsBoundary.PermissionsBoundaryArn != ""
	}
	return false
}

// iamManipAppendUnique appends every non-empty value of vals to dst that is not
// already present, preserving first-seen order. Mirrors the dedup in the
// composites' allow_sources aggregation.
func iamManipAppendUnique(dst []string, vals []string) []string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		found := false
		for _, e := range dst {
			if e == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}
