// This file ports the KMS 3-layer authorization model
// (core/graph/edges/kms/_kms_auth_helpers.py): key-policy parsing, the composed
// key-policy / IAM-delegation / grant evaluation (kmsCanPerformAction) that gates
// every KMS edge, and the principal / action / resource / ARN matchers and
// grant-constraint helpers it relies on, together with the grant-op mapping and
// non-grantable-action tables. The family entry point (KMSEdges), the
// SimpleKmsEdgeProcessor spec / grantable-operation tables, and the edge builders
// live in kms.go.
package edges

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/model"
)

// kmsStarResource is the default resource list ("*") used when a key-policy
// statement omits Resource — KMS key policies use "*" to name the key itself.
var kmsStarResource = []string{"*"}

// kmsActionToGrantOp maps an IAM action to its KMS grant operation name. Ported
// from _kms_auth_helpers._ACTION_TO_GRANT_OP; only actions present here can be
// satisfied by a Layer-3 grant.
var kmsActionToGrantOp = map[string]string{
	"kms:Decrypt":                         "Decrypt",
	"kms:Encrypt":                         "Encrypt",
	"kms:GenerateDataKey":                 "GenerateDataKey",
	"kms:GenerateDataKeyWithoutPlaintext": "GenerateDataKeyWithoutPlaintext",
	"kms:ReEncryptFrom":                   "ReEncryptFrom",
	"kms:ReEncryptTo":                     "ReEncryptTo",
	"kms:Sign":                            "Sign",
	"kms:Verify":                          "Verify",
	"kms:GenerateMac":                     "GenerateMac",
	"kms:VerifyMac":                       "VerifyMac",
	"kms:DescribeKey":                     "DescribeKey",
	"kms:CreateGrant":                     "CreateGrant",
	"kms:RetireGrant":                     "RetireGrant",
	"kms:DeriveSharedSecret":              "DeriveSharedSecret",
}

// kmsNonGrantableActions are the actions that a KMS grant can never delegate.
// Ported from _kms_auth_helpers._NON_GRANTABLE_ACTIONS; Layer 3 returns
// allowed=false for any of these (covers PutKeyPolicy/ScheduleKeyDeletion/
// DisableKey among the edge actions).
var kmsNonGrantableActions = map[string]bool{
	"kms:PutKeyPolicy":              true,
	"kms:ScheduleKeyDeletion":       true,
	"kms:CancelKeyDeletion":         true,
	"kms:DisableKey":                true,
	"kms:EnableKey":                 true,
	"kms:DisableKeyRotation":        true,
	"kms:EnableKeyRotation":         true,
	"kms:UpdateKeyDescription":      true,
	"kms:ListKeys":                  true,
	"kms:ListAliases":               true,
	"kms:ListGrants":                true,
	"kms:CreateAlias":               true,
	"kms:DeleteAlias":               true,
	"kms:UpdateAlias":               true,
	"kms:TagResource":               true,
	"kms:UntagResource":             true,
	"kms:ImportKeyMaterial":         true,
	"kms:DeleteImportedKeyMaterial": true,
	"kms:ReplicateKey":              true,
	"kms:UpdatePrimaryRegion":       true,
}

// kmsKeyPolicy is a key's parsed key policy plus precomputed IAM-delegation
// statements, threaded through per-principal checks so policy JSON is parsed once.
type kmsKeyPolicy struct {
	statements  []eval.Statement
	delegations []eval.MatchedStatement
	truthy      bool // the raw KeyPolicy was a non-empty object (Python `if key_policy`)
	known       bool // collection succeeded, or a legacy artifact contains a valid policy
}

// kmsCompileKeyPolicy parses key.KeyPolicy and precomputes IAM delegation.
func kmsCompileKeyPolicy(key *model.KMSKey, accountID string) kmsKeyPolicy {
	statements, truthy := kmsParseKeyPolicy(key)
	return kmsKeyPolicy{
		statements:  statements,
		delegations: kmsIAMDelegations(statements, accountID),
		truthy:      truthy,
		known:       key.KeyPolicyKnown || truthy,
	}
}

// kmsParseKeyPolicy returns a key policy's statements and whether the raw policy
// was "truthy" — a non-empty JSON object. Ported from the `if not key_policy`
// guards: a null/absent/empty-object policy is falsy (statements nil, truthy
// false); a non-empty object with no Statement array is truthy with no statements
// (delegates=false, no direct grant). Key policies are plain JSON (not
// url-encoded), so they parse via ParseResourcePolicy, not ParsePolicyDocument.
func kmsParseKeyPolicy(key *model.KMSKey) ([]eval.Statement, bool) {
	raw := bytes.TrimSpace(key.KeyPolicy)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, false
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil || len(probe) == 0 {
		return nil, false
	}
	pol, err := eval.ParseResourcePolicy(raw)
	if err != nil || pol == nil {
		return nil, true
	}
	return pol.Statements, true
}

// kmsCanPerformAction evaluates the full 3-layer KMS authorization model for one
// (key, principal, action). Ported from _kms_auth_helpers.can_perform_kms_action:
// key policy (deny-wins, then allow), then IAM if the key delegates, then grants.
// Unknown key-policy collection fails closed before all three layers.
func kmsCanPerformAction(pe *eval.PolicyEvaluator, key *model.KMSKey, kp kmsKeyPolicy, principalArn, action string) *eval.PermissionCheckResult {
	if !kp.known {
		return &eval.PermissionCheckResult{Allowed: false}
	}
	requestContext := kmsDirectRequestContext(pe, key.Arn, principalArn, action)

	// Layer 1: key policy direct allow/deny.
	l1 := kmsCheckKeyPolicyAllows(kp, key.Arn, principalArn, action, requestContext)
	if l1.Denied {
		return l1
	}
	if l1.Allowed {
		return l1
	}

	// Layer 2: IAM policy — only when the key policy delegates to IAM.
	delegation := kmsCheckIAMDelegation(kp, requestContext)
	if delegation.Allowed {
		iam := pe.CanPerformAction(principalArn, action, key.Arn, requestContext)
		if iam.Denied {
			return iam
		}
		if iam.Allowed {
			return kmsDelegatedIAMResult(delegation, iam)
		}
	}

	// Layer 3: grants.
	grant := kmsCheckGrantAllows(key, principalArn, action)
	if grant.Allowed {
		return grant
	}

	return &eval.PermissionCheckResult{Allowed: false}
}

// kmsCheckKeyPolicyAllows checks whether the key policy directly allows (or
// denies) the principal the action. Ported from
// _kms_auth_helpers.check_key_policy_allows: match Allow/Deny statements on
// action (exact membership in {action, "kms:*", "*"}), resource (the key ARN,
// defaulting to "*"), and principal (root NOT expanded — direct grants only),
// then defer to the shared allow/deny arbiter. Conditions resolve against the
// store-backed direct-KMS context, including CallerAccount and an absent
// ViaService, so service-only grants cannot become direct relationships.
func kmsCheckKeyPolicyAllows(kp kmsKeyPolicy, keyArn, principalArn, action string, requestContext *eval.RequestContext) *eval.PermissionCheckResult {
	if !kp.truthy {
		return &eval.PermissionCheckResult{Allowed: false}
	}
	if keyArn == "" {
		keyArn = "*"
	}
	actionLower := strings.ToLower(action)

	var matchedAllows, matchedDenies []eval.MatchedStatement
	for i := range kp.statements {
		st := &kp.statements[i]
		if st.Effect != "Allow" && st.Effect != "Deny" {
			continue
		}
		if !kmsActionMatches(st.Action, actionLower) {
			continue
		}
		resources := st.Resource
		if resources == nil {
			resources = kmsStarResource
		}
		if !kmsAnyResourceMatches(resources, keyArn) {
			continue
		}
		// Direct-allow: do NOT expand root. Root-with-kms:* is the Layer-2
		// delegation pattern; only specific principals count as direct grants.
		if !kmsCheckPrincipalBlock(st.Principal, principalArn, false) {
			continue
		}
		ms := eval.MatchedStatement{Condition: st.Condition, Source: fmt.Sprintf("KeyPolicy/%d", i)}
		if st.Effect == "Allow" {
			matchedAllows = append(matchedAllows, ms)
		} else {
			matchedDenies = append(matchedDenies, ms)
		}
	}

	if len(matchedAllows) == 0 && len(matchedDenies) == 0 {
		return &eval.PermissionCheckResult{Allowed: false}
	}

	res := eval.ResolveMatchedStatements(matchedAllows, matchedDenies, func() *eval.RequestContext {
		return requestContext
	})
	return &eval.PermissionCheckResult{
		Allowed:      res.Allowed,
		Denied:       res.Denied,
		Conditions:   res.Conditions,
		AllowSources: res.AllowSources,
		DenySources:  res.DenySources,
	}
}

// kmsIAMDelegations returns the broad account-root allows that delegate the key
// to IAM. Wildcard principals are direct key-policy grants, not delegation, and
// absent policies never delegate.
func kmsIAMDelegations(statements []eval.Statement, accountID string) []eval.MatchedStatement {
	accountRoot := "arn:aws:iam::" + accountID + ":root"
	var delegations []eval.MatchedStatement
	for i := range statements {
		st := &statements[i]
		if st.Effect != "Allow" {
			continue
		}
		if !kmsHasBroadAction(st.Action) {
			continue
		}
		if kmsDelegatesToAccount(st.Principal, accountRoot) {
			delegations = append(delegations, eval.MatchedStatement{
				Condition: st.Condition,
				Source:    fmt.Sprintf("KeyPolicy/%d", i),
			})
		}
	}
	return delegations
}

// kmsCheckIAMDelegation resolves the key-policy half of IAM delegation against
// the same direct-KMS request context used for the identity statement.
func kmsCheckIAMDelegation(kp kmsKeyPolicy, requestContext *eval.RequestContext) *eval.PermissionCheckResult {
	res := eval.ResolveMatchedStatements(kp.delegations, nil, func() *eval.RequestContext {
		return requestContext
	})
	return &eval.PermissionCheckResult{
		Allowed:      res.Allowed,
		Conditions:   res.Conditions,
		AllowSources: res.AllowSources,
	}
}

// kmsDelegatedIAMResult preserves both sides of the authorization proof: the
// account-root key-policy delegation and the identity-policy grant it activates.
func kmsDelegatedIAMResult(delegation, identity *eval.PermissionCheckResult) *eval.PermissionCheckResult {
	return &eval.PermissionCheckResult{
		Allowed:      true,
		Outcome:      eval.OutcomeAllowed,
		Conditions:   append(append([]map[string]any(nil), delegation.Conditions...), identity.Conditions...),
		AllowSources: append(append([]string(nil), delegation.AllowSources...), identity.AllowSources...),
	}
}

// kmsDelegatesToAccount matches only an explicit account/root AWS principal.
func kmsDelegatesToAccount(principal *eval.Principal, accountRoot string) bool {
	if principal == nil || principal.Wildcard {
		return false
	}
	for _, entry := range principal.AWS {
		if isTwelveDigit(entry) {
			entry = "arn:aws:iam::" + entry + ":root"
		}
		if entry == accountRoot {
			return true
		}
	}
	return false
}

// kmsDirectRequestContext describes an unmediated principal-to-KMS call. The
// caller account is known from the principal ARN, while kms:ViaService is known
// to be absent. KMS policies requiring an AWS service therefore cannot become a
// direct edge through attacker bias.
func kmsDirectRequestContext(pe *eval.PolicyEvaluator, keyArn, principalArn, action string) *eval.RequestContext {
	base := pe.ResourcePolicyContext(principalArn, action, keyArn)
	values := make(map[string]string, len(base.Values)+1)
	for key, value := range base.Values {
		values[key] = value
	}
	if parts := strings.Split(principalArn, ":"); len(parts) > 4 && parts[4] != "" {
		values["kms:calleraccount"] = parts[4]
	}
	knownKeys := make(map[string]bool, len(base.KnownKeys)+2)
	for key, known := range base.KnownKeys {
		knownKeys[key] = known
	}
	knownKeys["kms:calleraccount"] = true
	knownKeys["kms:viaservice"] = true
	return &eval.RequestContext{
		Values:         values,
		KnownKeys:      knownKeys,
		PrincipalTags:  base.PrincipalTags,
		ResourceTags:   base.ResourceTags,
		PrincipalKnown: base.PrincipalKnown,
		ResourceKnown:  base.ResourceKnown,
		OrgDataKnown:   base.OrgDataKnown,
	}
}

// kmsCheckGrantAllows checks whether any grant on the key names the principal as
// grantee for the action's grant operation. Ported from
// _kms_auth_helpers.check_grant_allows: non-grantable actions and actions with no
// grant-op mapping return false; a matching grant yields allowed=true with source
// "Grant/<id>" and, when the grant is constrained, a GrantConstraints condition.
func kmsCheckGrantAllows(key *model.KMSKey, principalArn, action string) *eval.PermissionCheckResult {
	if kmsNonGrantableActions[action] {
		return &eval.PermissionCheckResult{Allowed: false}
	}
	grantOp, ok := kmsActionToGrantOp[action]
	if !ok {
		return &eval.PermissionCheckResult{Allowed: false}
	}
	for i := range key.Grants {
		g := &key.Grants[i]
		if g.GranteePrincipal != principalArn {
			continue
		}
		if !kmsContains(g.Operations, grantOp) {
			continue
		}
		grantID := g.GrantId
		if grantID == "" {
			grantID = "unknown"
		}
		var conditions []map[string]any
		if kmsConstraintsPresent(g.Constraints) {
			conditions = []map[string]any{{"GrantConstraints": g.Constraints}}
		}
		return &eval.PermissionCheckResult{
			Allowed:      true,
			AllowSources: []string{"Grant/" + grantID},
			Conditions:   conditions,
		}
	}
	return &eval.PermissionCheckResult{Allowed: false}
}

// kmsCheckPrincipalBlock reports whether a key-policy Principal block names the
// principal. Ported from _kms_auth_helpers._check_principal_block: a "*" block
// matches anyone; otherwise only AWS entries are considered (Service/Federated
// principals never produce these edges). expandRoot controls whether a ":root"
// entry expands to every principal in that account (Layer-2 delegation) or must
// match literally (Layer-1 direct grant).
func kmsCheckPrincipalBlock(p *eval.Principal, principalArn string, expandRoot bool) bool {
	if p == nil {
		return false
	}
	if p.Wildcard {
		return true
	}
	for _, entry := range p.AWS {
		if kmsPrincipalMatchesEntry(entry, principalArn, expandRoot) {
			return true
		}
	}
	return false
}

// kmsPrincipalMatchesEntry matches one AWS principal entry against a principal
// ARN. Ported from _kms_auth_helpers._principal_matches_key_policy_entry: "*"
// matches all; a bare 12-digit account normalizes to its root ARN; a ":root"
// entry with expandRoot matches every principal in that account; otherwise it is
// a case-sensitive '*'/'?' ARN glob (so a literal root ARN without expansion
// matches only the literal root principal).
func kmsPrincipalMatchesEntry(entry, principalArn string, expandRoot bool) bool {
	if entry == "*" {
		return true
	}
	if isTwelveDigit(entry) {
		entry = "arn:aws:iam::" + entry + ":root"
	}
	if expandRoot && strings.HasSuffix(entry, ":root") {
		parts := strings.Split(entry, ":")
		if len(parts) >= 5 {
			entryAccount := parts[4]
			principalAccount := ""
			if pp := strings.Split(principalArn, ":"); len(pp) >= 5 {
				principalAccount = pp[4]
			}
			return entryAccount == principalAccount
		}
	}
	return kmsArnMatches(entry, principalArn)
}

// kmsActionMatches reports whether a statement's actions include the action.
// Ported from check_key_policy_allows' action test: exact (case-insensitive)
// membership in {action, "kms:*", "*"} — NOT a general action glob.
func kmsActionMatches(stmtActions []string, actionLower string) bool {
	for _, a := range stmtActions {
		al := strings.ToLower(a)
		if al == actionLower || al == "kms:*" || al == "*" {
			return true
		}
	}
	return false
}

// kmsHasBroadAction reports whether a statement grants a broad KMS action (kms:*
// or "*"). Ported from key_policy_delegates_to_iam's has_broad_action test.
func kmsHasBroadAction(stmtActions []string) bool {
	for _, a := range stmtActions {
		al := strings.ToLower(a)
		if al == "kms:*" || al == "*" {
			return true
		}
	}
	return false
}

// kmsAnyResourceMatches reports whether any resource pattern matches the key ARN
// ("*" always matches — key policies use it for the key itself).
func kmsAnyResourceMatches(resources []string, keyArn string) bool {
	for _, r := range resources {
		if r == "*" || kmsArnMatches(r, keyArn) {
			return true
		}
	}
	return false
}

// kmsArnMatches reports whether arn matches an AWS wildcard pattern ('*' = any
// sequence, '?' = any single char), case-sensitive and anchored. A linear
// two-pointer stand-in for _kms_auth_helpers._arn_matches' anchored regex.
func kmsArnMatches(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	p := []rune(pattern)
	t := []rune(arn)
	pi, ti := 0, 0
	starPi, starTi := -1, -1
	for ti < len(t) {
		if pi < len(p) && p[pi] == '*' {
			starPi, starTi = pi, ti
			pi++
			continue
		}
		if pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]) {
			pi++
			ti++
			continue
		}
		if starPi >= 0 {
			pi = starPi + 1
			starTi++
			ti = starTi
			continue
		}
		return false
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// kmsConstraintsPresent reports whether a grant carries encryption-context
// constraints (Python `if constraints:` — a truthy constraints dict).
func kmsConstraintsPresent(c model.KMSGrantConstraints) bool {
	return len(c.EncryptionContextEquals) > 0 || len(c.EncryptionContextSubset) > 0
}

// kmsContains reports set membership in a string slice.
func kmsContains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
