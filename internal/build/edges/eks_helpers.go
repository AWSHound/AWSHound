// This file holds the EKS family's trust-document parsing and generic helpers used
// by the edge processors in eks.go: the IRSA trust-policy scan and condition
// extraction (with the eksIRSAConds carrier), cluster-name and access-entry ARN
// synthesis, the service-trust check, the raw trust-JSON parser, the AWS
// string/list normalisers, and the small permission / dedup / Python-truthiness
// utilities.
package edges

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// eksIRSAConds holds the sub/aud scoping pulled from a matching IRSA trust
// statement. subject / audience are the RAW JSON condition values (string or list),
// kept as `any` so eksTruthyJSON reproduces the Python json.dumps of the original
// value exactly. The audience operator is intentionally absent: the IRSA edge never
// emits an irsa_audience_operator property (the Python captures it but discards it).
type eksIRSAConds struct {
	subject         any
	subjectOperator string
	audience        any
}

// eksRoleTrustsOIDCIssuer ports _role_trusts_oidc_issuer: reports whether a role's
// trust policy has an Allow statement whose Principal.Federated references
// issuerPath, returning the sub/aud conditions from the FIRST such statement.
func eksRoleTrustsOIDCIssuer(trustDoc map[string]any, issuerPath string) (bool, eksIRSAConds) {
	for _, s := range eksStatementList(trustDoc["Statement"]) {
		stmt, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if eff, _ := stmt["Effect"].(string); eff != "Allow" {
			continue
		}
		// Python skips any Principal that is not a dict (e.g. bare "*").
		principalBlock, ok := stmt["Principal"].(map[string]any)
		if !ok {
			continue
		}
		for _, fed := range eksStringOrList(principalBlock["Federated"]) {
			if strings.Contains(fed, issuerPath) {
				return true, eksExtractIRSAConditions(stmt, issuerPath)
			}
		}
	}
	return false, eksIRSAConds{}
}

// eksExtractIRSAConditions ports _extract_irsa_conditions: scan a trust statement's
// Condition block for keys containing issuerPath and ending in :sub / :aud, across
// every condition operator, capturing the value and (for sub) the operator.
func eksExtractIRSAConditions(stmt map[string]any, issuerPath string) eksIRSAConds {
	var out eksIRSAConds
	condBlock, ok := stmt["Condition"].(map[string]any)
	if !ok || len(condBlock) == 0 {
		return out
	}
	for operator, raw := range condBlock {
		conditions, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for key, value := range conditions {
			if !strings.Contains(key, issuerPath) {
				continue
			}
			switch {
			case strings.HasSuffix(key, ":sub"):
				out.subject = value
				out.subjectOperator = operator
			case strings.HasSuffix(key, ":aud"):
				out.audience = value
			}
		}
	}
	return out
}

// eksClusterNameToARN rebuilds AWSHound's ingest-time cluster_name -> ARN map for one
// account (ingest_eks's cluster_name_to_arn), used to denormalise a node group /
// association's clusterName to the parent cluster ARN. Only clusters with both an ARN
// and a name are included; on a name collision the last wins, as in the Python dict.
func eksClusterNameToARN(a *store.Account) map[string]string {
	out := make(map[string]string)
	for _, c := range a.EKSClusterList() {
		if c.Arn == "" || c.Name == "" {
			continue
		}
		out[c.Name] = c.Arn
	}
	return out
}

// eksClusterARNToAccessEntryARN ports _cluster_arn_to_access_entry_arn: build a
// synthetic access-entry ARN from a cluster ARN so eks:AssociateAccessPolicy (which
// authorises against the not-yet-created access-entry resource) resolves against IAM
// patterns like arn:aws:eks:*:*:access-entry/*. Returns ok=false for a malformed
// cluster ARN (fewer than 6 segments, or no "/" in the resource segment) — the
// Python raises on these; real cluster ARNs never hit it.
func eksClusterARNToAccessEntryARN(clusterARN string) (string, bool) {
	parts := strings.Split(clusterARN, ":")
	if len(parts) < 6 {
		return "", false
	}
	partition := parts[1]
	region := parts[3]
	account := parts[4]
	resource := parts[5]
	slash := strings.Index(resource, "/")
	if slash < 0 {
		return "", false
	}
	clusterName := resource[slash+1:]
	return "arn:" + partition + ":eks:" + region + ":" + account +
		":access-entry/" + clusterName + "/type/principal-id/entry-id", true
}

// eksRoleTrustsService ports _service_trust_helpers.role_trusts_service: whether a
// role's trust policy has an Allow statement naming servicePrincipal in
// Principal.Service (a bare "*" principal trusts every service).
func eksRoleTrustsService(role *model.RoleDetail, servicePrincipal string) bool {
	if role == nil || role.AssumeRolePolicyDocument == "" {
		return false
	}
	doc, err := eval.ParsePolicyDocument(role.AssumeRolePolicyDocument)
	if err != nil || doc == nil {
		return false
	}
	for i := range doc.Statements {
		st := &doc.Statements[i]
		if st.Effect != "Allow" || st.Principal == nil {
			continue
		}
		if st.Principal.Wildcard {
			return true
		}
		for _, svc := range st.Principal.Service {
			if svc == servicePrincipal {
				return true
			}
		}
	}
	return false
}

// eksParseTrustDocRaw URL-decodes (url.PathUnescape, matching eval.ParsePolicyDocument
// and Python's urllib.parse.unquote) and JSON-parses a role's AssumeRolePolicyDocument
// into a generic map, returning nil for an empty or unparseable document. The raw map
// (not eval.Policy) is used for IRSA so scalar vs list condition values survive to
// serialisation.
func eksParseTrustDocRaw(encoded string) map[string]any {
	if encoded == "" {
		return nil
	}
	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		decoded = encoded
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(decoded), &m); err != nil {
		return nil
	}
	return m
}

// eksStatementList normalises a policy's "Statement" value to a slice: a list is
// returned as-is; a single statement object is wrapped in a one-element slice (AWS
// permits either form); anything else yields nil.
func eksStatementList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case map[string]any:
		return []any{x}
	default:
		return nil
	}
}

// eksStringOrList normalises an AWS string-or-array field to a []string of its string
// elements (a bare string becomes a one-element slice; non-string elements are
// skipped).
func eksStringOrList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// eksFirstAllowedCluster returns the first cluster ARN's PermissionCheckResult where
// the principal is allowed the action (short-circuits), or nil when none allow it.
func eksFirstAllowedCluster(pe *eval.PolicyEvaluator, principal, action string, clusterARNs []string) *eval.PermissionCheckResult {
	for _, clusterARN := range clusterARNs {
		if res := pe.CanPerformAction(principal, action, clusterARN, nil); res.Allowed {
			return res
		}
	}
	return nil
}

// eksDedupPreserve returns the order-preserving de-duplication of a string slice
// (Python's list(dict.fromkeys(...))). Empty strings are kept — the Pod Identity
// processor de-dupes with dict.fromkeys and does not skip them.
func eksDedupPreserve(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// eksTruthyJSON reproduces `json.dumps(v) if v else ""`: "" for a Python-falsy value
// (nil, "", empty list) and the compact JSON encoding otherwise. A scalar string
// value serialises as a JSON string and a list as a JSON array, exactly as the Python
// json.dumps of the raw condition value does.
func eksTruthyJSON(v any) string {
	if !eksPyTruthy(v) {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// eksPyTruthy reports Python truthiness for the JSON-decoded value kinds that appear
// in a condition value: nil/""/0/false/empty-collection are falsy, everything else
// truthy. Used both for the irsa_subject/irsa_audience guards and is_scoped.
func eksPyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}
