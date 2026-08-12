// This file ports the trust / compute-execution / organization-policy half of the
// STRUCTURAL family (core/graph/edges/structural/): the Trusts, TrustedBy,
// TrustsSAMLProvider, TrustsOIDCProvider, RunsAs, HasSCP, and HasRCP processors,
// together with the shared trust-document parsing and org SCP/RCP indexing helpers.
// The containment and policy/group-attachment half lives in structural.go, which
// also carries the StructuralEdges entry point and the package doc comment.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// structuralTrusts ports TrustsEdgeProcessor (AWS_Trusts, non-traversable): role ->
// each AWS/Service principal its trust policy admits (Allow statements only).
// Federated principals are excluded here — they are emitted by the
// TrustsSAMLProvider / TrustsOIDCProvider edges.
func structuralTrusts(a *store.Account) []*graph.Edge {
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Roles) {
		role := a.Roles[arn]
		for _, trusted := range structuralRoleTrustedPrincipals(role) {
			out = structuralAppend(out, role.Arn, trusted, graph.KindTrusts, false)
		}
	}
	return out
}

// structuralTrustedBy ports TrustedByEdgeProcessor (AWS_TrustedBy,
// non-traversable): the inverse of Trusts — trusted principal -> role.
func structuralTrustedBy(a *store.Account) []*graph.Edge {
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Roles) {
		role := a.Roles[arn]
		for _, trusted := range structuralRoleTrustedPrincipals(role) {
			out = structuralAppend(out, trusted, role.Arn, graph.KindTrustedBy, false)
		}
	}
	return out
}

// structuralTrustsSAMLProvider ports TrustsSamlProviderEdgeProcessor
// (AWS_TrustsSAMLProvider, non-traversable): role -> SAML provider, for every
// Principal.Federated ARN in an Allow statement that names a SAML provider.
func structuralTrustsSAMLProvider(a *store.Account) []*graph.Edge {
	return structuralTrustsFederated(a, ":saml-provider/", graph.KindTrustsSAMLProvider)
}

// structuralTrustsOIDCProvider ports TrustsOidcProviderEdgeProcessor
// (AWS_TrustsOIDCProvider, non-traversable): role -> OIDC provider, for every
// Principal.Federated ARN in an Allow statement that names an OIDC provider.
func structuralTrustsOIDCProvider(a *store.Account) []*graph.Edge {
	return structuralTrustsFederated(a, ":oidc-provider/", graph.KindTrustsOIDCProvider)
}

// structuralTrustsFederated is the shared body of the SAML/OIDC federation trust
// edges: role -> federated provider for each Principal.Federated ARN (in an Allow
// statement) whose value contains marker (":saml-provider/" or ":oidc-provider/").
func structuralTrustsFederated(a *store.Account, marker string, kind graph.EdgeKind) []*graph.Edge {
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Roles) {
		role := a.Roles[arn]
		doc := structuralParseTrustDoc(role)
		if doc == nil {
			continue
		}
		for i := range doc.Statements {
			st := &doc.Statements[i]
			if st.Effect != "Allow" {
				continue
			}
			for _, fed := range structuralFederatedPrincipals(st.Principal) {
				if strings.Contains(fed, marker) {
					out = structuralAppend(out, role.Arn, fed, kind, false)
				}
			}
		}
	}
	return out
}

// structuralRunsAs ports RunsAsEdgeProcessor (AWS_RunsAs, traversable): a compute
// resource -> the IAM role it executes as. Lambda functions and CloudFormation
// stacks carry their role directly; EC2 instances resolve it through the instance
// profile -> role mapping. Every edge is traversable.
func structuralRunsAs(a *store.Account) []*graph.Edge {
	accountID := a.ID
	var out []*graph.Edge

	// Lambda functions -> execution roles.
	for _, fn := range a.LambdaFunctionList() {
		if fn.FunctionArn == "" || fn.Role == "" {
			continue
		}
		out = structuralAppend(out, fn.FunctionArn, fn.Role, graph.KindRunsAs, true)
	}

	// CloudFormation stacks -> execution roles.
	for _, stack := range a.CloudFormationStackList() {
		if stack.StackId == "" || stack.RoleARN == "" {
			continue
		}
		out = structuralAppend(out, stack.StackId, stack.RoleARN, graph.KindRunsAs, true)
	}

	// EC2 instances -> roles via instance profiles.
	profileToRole := structuralInstanceProfileToRole(a)
	for _, inst := range a.EC2InstanceList() {
		if inst.InstanceId == "" || inst.IamInstanceProfile == nil {
			continue
		}
		profileArn := inst.IamInstanceProfile.Arn
		if profileArn == "" {
			continue
		}
		roleArn := profileToRole[profileArn]
		if roleArn == "" {
			continue
		}
		out = structuralAppend(out, ec2InstanceARN(accountID, inst), roleArn, graph.KindRunsAs, true)
	}

	return out
}

// structuralHasSCP ports HasScpEdgeProcessor (AWS_HasSCP, non-traversable):
// account root -> each service-control policy that applies to this account (per
// the precomputed by-account index).
func structuralHasSCP(a *store.Account, scpByAccount map[string][]string) []*graph.Edge {
	accountArn := accountRootARN(a.ID)
	var out []*graph.Edge
	for _, scpArn := range scpByAccount[a.ID] {
		out = structuralAppend(out, accountArn, scpArn, graph.KindHasSCP, false)
	}
	return out
}

// structuralHasRCP ports HasRcpEdgeProcessor (AWS_HasRCP, non-traversable):
// account root -> each resource-control policy that applies to this account.
func structuralHasRCP(a *store.Account, rcpByAccount map[string][]string) []*graph.Edge {
	accountArn := accountRootARN(a.ID)
	var out []*graph.Edge
	for _, rcpArn := range rcpByAccount[a.ID] {
		out = structuralAppend(out, accountArn, rcpArn, graph.KindHasRCP, false)
	}
	return out
}

// structuralOrgPolicyIndex builds the account -> [SCP arns] and account -> [RCP
// arns] maps used by HasSCP / HasRCP. It ports the Python store's
// _index_organization_data: for each org policy, every account id in its resolved
// AccountIds target set gets the policy's ARN. Policies are gathered across all
// accounts (they are stored on whichever account ingested the org data) and
// de-duplicated by ARN, then expanded in ARN order so each account's list is
// deterministic.
func structuralOrgPolicyIndex(accounts []*store.Account) (scp, rcp map[string][]string) {
	scpSeen := make(map[string]bool)
	rcpSeen := make(map[string]bool)
	var scps []*model.SCPPolicy
	var rcps []*model.RCPPolicy
	for _, a := range accounts {
		for _, p := range a.SCPPolicyList() {
			if p.Arn == "" || scpSeen[p.Arn] {
				continue
			}
			scpSeen[p.Arn] = true
			scps = append(scps, p)
		}
		for _, p := range a.RCPPolicyList() {
			if p.Arn == "" || rcpSeen[p.Arn] {
				continue
			}
			rcpSeen[p.Arn] = true
			rcps = append(rcps, p)
		}
	}
	sort.Slice(scps, func(i, j int) bool { return scps[i].Arn < scps[j].Arn })
	sort.Slice(rcps, func(i, j int) bool { return rcps[i].Arn < rcps[j].Arn })

	scp = make(map[string][]string)
	for _, p := range scps {
		for _, accountID := range p.AccountIds {
			scp[accountID] = append(scp[accountID], p.Arn)
		}
	}
	rcp = make(map[string][]string)
	for _, p := range rcps {
		for _, accountID := range p.AccountIds {
			rcp[accountID] = append(rcp[accountID], p.Arn)
		}
	}
	return scp, rcp
}

// structuralInstanceProfileToRole builds {instance_profile_arn: role_arn} for the
// account, porting get_instance_profile_to_role_mapping: each role's
// InstanceProfileList names the profiles that wrap it, so every profile ARN maps
// back to that role's ARN. Roles are iterated in sorted ARN order for
// determinism (an instance profile wraps exactly one role in AWS, so there is no
// real conflict).
func structuralInstanceProfileToRole(a *store.Account) map[string]string {
	out := make(map[string]string)
	for _, arn := range sortedKeys(a.Roles) {
		role := a.Roles[arn]
		for i := range role.InstanceProfileList {
			if profileArn := role.InstanceProfileList[i].Arn; profileArn != "" {
				out[profileArn] = role.Arn
			}
		}
	}
	return out
}

// structuralRoleTrustedPrincipals returns the AWS + Service principals a role's
// assume-role policy trusts, across every Allow statement. It ports
// PolicyEvaluator.extract_trusted_principals applied over the trust document:
// bare 12-digit account ids normalize to their :root ARN, a bare "*" principal
// yields "*", and Principal.Federated is excluded (its providers are emitted by
// the federation-trust edges).
func structuralRoleTrustedPrincipals(role *model.RoleDetail) []string {
	doc := structuralParseTrustDoc(role)
	if doc == nil {
		return nil
	}
	var out []string
	for i := range doc.Statements {
		st := &doc.Statements[i]
		if st.Effect != "Allow" {
			continue
		}
		out = append(out, structuralExtractTrustedPrincipals(st.Principal)...)
	}
	return out
}

// structuralExtractTrustedPrincipals ports extract_trusted_principals for a single
// parsed Principal block: a bare "*" yields ["*"]; otherwise each Principal.AWS
// entry (12-digit account ids normalized to arn:aws:iam::<id>:root) followed by
// each Principal.Service entry. Federated principals are intentionally omitted.
func structuralExtractTrustedPrincipals(p *eval.Principal) []string {
	if p == nil {
		return nil
	}
	if p.Wildcard {
		return []string{"*"}
	}
	out := make([]string, 0, len(p.AWS)+len(p.Service))
	for _, entry := range p.AWS {
		if isTwelveDigit(entry) {
			out = append(out, "arn:aws:iam::"+entry+":root")
		} else {
			out = append(out, entry)
		}
	}
	out = append(out, p.Service...)
	return out
}

// structuralFederatedPrincipals ports _extract_federated_principals: the
// Principal.Federated ARNs of a parsed Principal block (empty for a bare "*" or a
// non-federated block).
func structuralFederatedPrincipals(p *eval.Principal) []string {
	if p == nil {
		return nil
	}
	return p.Federated
}

// structuralParseTrustDoc parses a role's URL-encoded AssumeRolePolicyDocument via
// the shared evaluator parser (which url-decodes then JSON-parses, accepting a
// single statement or an array). It returns nil for an absent or unparseable
// document, matching the Python's `if not trust_policy: continue` skip.
func structuralParseTrustDoc(role *model.RoleDetail) *eval.Policy {
	if role.AssumeRolePolicyDocument == "" {
		return nil
	}
	doc, err := eval.ParsePolicyDocument(role.AssumeRolePolicyDocument)
	if err != nil {
		return nil
	}
	return doc
}
