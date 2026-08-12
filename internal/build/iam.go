// Package build turns collected, store-resident AWS data into OpenGraph nodes.
// It is the Go port of AWSHound's core/graph/nodes package: one Nodes function
// per service reads the account's typed data and emits *graph.Node values with
// the correct kind and property set.
//
// This file ports the IAM node parsers — principals.py (AWSUser/AWSGroup/
// AWSRole), policies.py (AWSPolicy managed policies), and federation.py
// (AWSSAMLProvider/AWSOIDCProvider) — over the reused model shapes.
//
// Fidelity note: the reused model.* shapes (internal/model/types.go) deliberately
// omit several fields the Python nodes carry — principal/policy CreateDate,
// PolicyDetail UpdateDate/IsAttachable, RoleDetail MaxSessionDuration/RoleLastUsed,
// and provider CreateDate/ValidUntil. Those properties (create_date, update_date,
// is_attachable, max_session_duration, last_used_date, last_used_region,
// valid_until) are therefore not emitted here; every property the model can
// supply is ported faithfully, with the same keys, order, and semantics.
package build

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// IAMNodes emits the account's IAM identity, policy, and federation nodes:
// AWS_User, AWS_Group, AWS_Role, AWS_Policy, AWS_SAMLProvider, and
// AWS_OIDCProvider. Each category is emitted in ascending ARN order so the graph
// output is diff-stable. Node ids and the "arn" property carry the raw ARN; the
// colon->underscore id encoding is applied later by the emit package.
func IAMNodes(a *store.Account) []*graph.Node {
	accountID := a.ID
	var nodes []*graph.Node

	for _, arn := range sortedKeys(a.Users) {
		u := a.Users[arn]
		n := graph.NewNode(u.Arn, graph.KindUser)
		n.Set("name", accountID+":"+u.UserName)
		n.Set("user_name", u.UserName)
		n.Set("user_id", u.UserId)
		n.Set("arn", u.Arn)
		n.Set("path", iamPathOr(u.Path))
		n.Set("account_id", accountID)
		if u.PermissionsBoundary != nil {
			n.Set("permissions_boundary_arn", u.PermissionsBoundary.PermissionsBoundaryArn)
		}
		if len(u.Tags) > 0 {
			n.Set("tags", jsonProp(u.Tags))
		}
		if ip := iamInlinePolicyMap(u.UserPolicyList); ip != "" {
			n.Set("inline_policies", ip)
		}
		nodes = append(nodes, n)
	}

	for _, arn := range sortedKeys(a.Groups) {
		g := a.Groups[arn]
		n := graph.NewNode(g.Arn, graph.KindGroup)
		n.Set("name", accountID+":"+g.GroupName)
		n.Set("group_name", g.GroupName)
		n.Set("group_id", g.GroupId)
		n.Set("arn", g.Arn)
		n.Set("path", iamPathOr(g.Path))
		n.Set("account_id", accountID)
		if ip := iamInlinePolicyMap(g.GroupPolicyList); ip != "" {
			n.Set("inline_policies", ip)
		}
		nodes = append(nodes, n)
	}

	for _, arn := range sortedKeys(a.Roles) {
		r := a.Roles[arn]
		n := graph.NewNode(r.Arn, graph.KindRole)
		n.Set("name", accountID+":"+r.RoleName)
		n.Set("role_name", r.RoleName)
		n.Set("role_id", r.RoleId)
		n.Set("arn", r.Arn)
		n.Set("path", iamPathOr(r.Path))
		n.Set("account_id", accountID)
		if r.AssumeRolePolicyDocument != "" {
			n.Set("assume_role_policy_document", iamDecodeDocument(r.AssumeRolePolicyDocument))
		}
		if r.PermissionsBoundary != nil {
			n.Set("permissions_boundary_arn", r.PermissionsBoundary.PermissionsBoundaryArn)
		}
		if len(r.Tags) > 0 {
			n.Set("tags", jsonProp(r.Tags))
		}
		if ip := iamInlinePolicyMap(r.RolePolicyList); ip != "" {
			n.Set("inline_policies", ip)
		}
		nodes = append(nodes, n)
	}

	for _, arn := range sortedKeys(a.ManagedPolicies) {
		p := a.ManagedPolicies[arn]
		// AWS-managed policies belong to the "aws" pseudo-account.
		policyAccountID := accountID
		if strings.HasPrefix(p.Arn, "arn:aws:iam::aws:") {
			policyAccountID = "aws"
		}
		n := graph.NewNode(p.Arn, graph.KindPolicy)
		n.Set("name", policyAccountID+":"+p.PolicyName)
		n.Set("policy_name", p.PolicyName)
		n.Set("policy_id", p.PolicyId)
		n.Set("arn", p.Arn)
		n.Set("path", iamPathOr(p.Path))
		n.Set("default_version_id", p.DefaultVersionId)
		n.Set("attachment_count", p.AttachmentCount)
		n.Set("account_id", policyAccountID)
		// Store the default version's policy document.
		for i := range p.PolicyVersions {
			if p.PolicyVersions[i].IsDefaultVersion {
				if doc := p.PolicyVersions[i].Document; doc != "" {
					n.Set("policy_document", iamDecodeDocument(doc))
				}
				break
			}
		}
		nodes = append(nodes, n)
	}

	for _, arn := range sortedKeys(a.SAMLProviders) {
		sp := a.SAMLProviders[arn]
		name := iamLastPathSegment(sp.Arn)
		n := graph.NewNode(sp.Arn, graph.KindSAMLProvider)
		n.Set("name", accountID+":"+name)
		n.Set("arn", sp.Arn)
		n.Set("account_id", accountID)
		n.Set("collected", true)
		nodes = append(nodes, n)
	}

	for _, arn := range sortedKeys(a.OIDCProviders) {
		op := a.OIDCProviders[arn]
		providerURL := op.Url
		if providerURL == "" {
			providerURL = iamOIDCURLFromArn(op.Arn)
		}
		n := graph.NewNode(op.Arn, graph.KindOIDCProvider)
		n.Set("name", accountID+":"+providerURL)
		n.Set("url", providerURL)
		n.Set("arn", op.Arn)
		n.Set("account_id", accountID)
		n.Set("collected", true)
		if len(op.ClientIDList) > 0 {
			n.Set("client_id_list", op.ClientIDList)
		}
		if len(op.ThumbprintList) > 0 {
			n.Set("thumbprint_list", op.ThumbprintList)
		}
		nodes = append(nodes, n)
	}

	return nodes
}

// sortedKeys returns a map's keys sorted ascending, so node emission order is
// deterministic regardless of Go map iteration order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// iamPathOr returns path, or "/" when it is empty — the IAM path default, and the
// value the Python parsers use via .get("Path", "/").
func iamPathOr(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

// iamInlinePolicyMap builds the "inline_policies" property: a JSON object string
// mapping each inline policy name to its (decoded) policy document, mirroring
// principals.py's _inline_policy_map + json.dumps. Documents that are valid JSON
// are embedded as nested objects; otherwise they are embedded as JSON strings.
// Returns "" when there are no named inline policies (so the caller omits the
// property, matching the Python `if inline_policies:` guard).
func iamInlinePolicyMap(list []model.InlinePolicy) string {
	if len(list) == 0 {
		return ""
	}
	m := make(map[string]json.RawMessage, len(list))
	for _, p := range list {
		if p.PolicyName == "" {
			continue
		}
		m[p.PolicyName] = iamJSONValue(iamDecodeDocument(p.PolicyDocument))
	}
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// iamDecodeDocument URL-decodes a GAAD policy document. AWS delivers policy
// documents URL-encoded on the wire (and the model stores them as such); boto3
// transparently decodes them in the Python pipeline, so decoding here yields the
// equivalent plain-JSON text. A malformed encoding falls back to the raw string.
func iamDecodeDocument(s string) string {
	if s == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}

// iamJSONValue returns s as a JSON value: the raw bytes when s is already valid
// JSON (e.g. a decoded policy-document object), otherwise s encoded as a JSON
// string. Used to embed inline policy documents inside the inline_policies map.
func iamJSONValue(s string) json.RawMessage {
	if trimmed := strings.TrimSpace(s); trimmed != "" && json.Valid([]byte(trimmed)) {
		return json.RawMessage(trimmed)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return json.RawMessage(b)
}

// iamLastPathSegment returns the substring after the final "/", used to derive a
// SAML provider's display name from its ARN (arn.rsplit("/", 1)[-1]).
func iamLastPathSegment(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// iamOIDCURLFromArn derives an OIDC provider's URL from its ARN when the provider
// metadata carries no Url, matching federation.py's split on ":oidc-provider/".
func iamOIDCURLFromArn(arn string) string {
	const marker = ":oidc-provider/"
	if i := strings.Index(arn, marker); i >= 0 {
		return arn[i+len(marker):]
	}
	return ""
}
