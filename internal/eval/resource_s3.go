package eval

import (
	"strconv"
	"strings"
)

// This file ports AWSHound's S3 access-control evaluator across the three S3
// grant layers plus Block Public Access:
//
//   - core/evaluation/s3_policy_evaluator.py  -> S3Evaluator, EvaluateS3Access
//                                                (can_perform_s3_action), the BPA
//                                                logic, _has_public_policy,
//                                                _infer_bucket_account
//   - core/evaluation/_s3_bucket_policy.py    -> checkBucketPolicy
//   - core/evaluation/_s3_acl.py              -> checkACL
//
// S3 does not use the plain IAM model: within an account IAM OR bucket policy OR
// ACL can grant (union of allows); cross-account needs IAM AND bucket policy (or
// an independent ACL grant); an explicit deny on any layer wins; and Block Public
// Access can clip a public-policy bucket. This evaluator composes the identity
// side (IdentityEvaluator) with the bucket's own resource controls.

// S3ACLGrantee identifies who an ACL grant is for. Type is the grantee kind
// ("CanonicalUser", "Group", …); a Group grantee carries a URI (the AllUsers /
// AuthenticatedUsers group). Ported from the ACL grantee dict the Python reads.
type S3ACLGrantee struct {
	Type string
	ID   string
	URI  string
}

// S3ACLGrant pairs a grantee with the permission it was granted ("READ",
// "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL").
type S3ACLGrant struct {
	Grantee    S3ACLGrantee
	Permission string
}

// S3ACL is a bucket ACL — the meaningful subset (its grants) of a
// GetBucketAcl response. Ported from the ACL dict the Python evaluator consumes.
type S3ACL struct {
	Grants []S3ACLGrant
}

// PublicAccessBlock is an S3 Block Public Access setting, used both per-bucket
// and account-wide. Ported from the BPA dict the Python merges; the four flags
// mirror the AWS response.
type PublicAccessBlock struct {
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}

// S3BucketConfig is the resource-control configuration for one bucket. Ported
// from s3_policy_evaluator.S3BucketConfig.
//
// BucketPolicy is the parsed bucket policy (parse the raw, NON-url-encoded JSON
// via ParseResourcePolicy), nil when the bucket has none. ACL and
// BlockPublicAccess are nil when absent. OwnershipControls is the object-ownership
// setting ("BucketOwnerEnforced" disables ACLs entirely), "" when unset.
// OwnerAccountID is the bucket owner's account — the basis for cross-account
// determination; the caller sets it to the account the bucket was collected from.
type S3BucketConfig struct {
	BucketArn         string
	BucketPolicy      *Policy
	ACL               *S3ACL
	BlockPublicAccess *PublicAccessBlock
	OwnershipControls string
	OwnerAccountID    string
}

// S3AccessCheckResult is the outcome of an S3 access evaluation across every
// control mechanism. Ported field-for-field from
// s3_policy_evaluator.S3AccessCheckResult.
type S3AccessCheckResult struct {
	Allowed              bool
	IAMAllowed           bool
	BucketPolicyAllowed  bool
	ACLAllowed           bool
	Denied               bool
	DenySource           string
	AllowSources         []string
	Conditions           []map[string]any
	HasConditions        bool
	RequiresBucketPolicy bool
}

// actionToACLPermission maps an S3 action to the ACL permission level that
// grants it; a FULL_CONTROL grant is a superset of every level. Ported from
// _s3_acl._ACTION_TO_ACL_PERMISSION.
var actionToACLPermission = map[string]string{
	"s3:ListBucket":   "READ",
	"s3:GetObject":    "READ",
	"s3:PutObject":    "WRITE",
	"s3:GetBucketAcl": "READ_ACP",
	"s3:GetObjectAcl": "READ_ACP",
	"s3:PutBucketAcl": "WRITE_ACP",
	"s3:PutObjectAcl": "WRITE_ACP",
}

// S3Evaluator evaluates S3 access across IAM policies, bucket policies, ACLs, and
// Block Public Access. Ported from s3_policy_evaluator.S3PolicyEvaluator (the
// bucket_configs constructor path; the deprecated per-parameter path — and with
// it the object-level ACL override, which that path never populated under the
// runtime's bucket_configs wiring — is intentionally omitted).
//
// It is read-only after construction and, provided the IdentityEvaluator and
// ContextBuilder it holds are themselves safe for concurrent use, is safe for
// concurrent queries.
type S3Evaluator struct {
	identity                  IdentityEvaluator
	bucketConfigs             map[string]*S3BucketConfig
	accountPublicAccessBlocks map[string]*PublicAccessBlock
	contextBuilder            ContextBuilder
}

// NewS3Evaluator builds an S3Evaluator. bucketConfigs is keyed by bucket ARN
// (arn:aws:s3:::name); accountPublicAccessBlocks is keyed by account ID.
// contextBuilder is the policy-variable/condition context source (may be nil for
// a blank context). Mirrors S3PolicyEvaluator.__init__.
func NewS3Evaluator(
	identity IdentityEvaluator,
	bucketConfigs map[string]*S3BucketConfig,
	accountPublicAccessBlocks map[string]*PublicAccessBlock,
	contextBuilder ContextBuilder,
) *S3Evaluator {
	if bucketConfigs == nil {
		bucketConfigs = map[string]*S3BucketConfig{}
	}
	if accountPublicAccessBlocks == nil {
		accountPublicAccessBlocks = map[string]*PublicAccessBlock{}
	}
	return &S3Evaluator{
		identity:                  identity,
		bucketConfigs:             bucketConfigs,
		accountPublicAccessBlocks: accountPublicAccessBlocks,
		contextBuilder:            contextBuilder,
	}
}

// EvaluateS3Access checks whether principalArn can perform an S3 action on the
// resource (a bucket or object ARN). Ported from
// S3PolicyEvaluator.can_perform_s3_action.
//
// The evaluation order: any explicit deny (IAM, then bucket policy, then a Block
// Public Access clip) wins immediately; otherwise the allow layers are combined —
// cross-account requires IAM AND bucket policy (or an independent ACL grant),
// same-account takes the union of IAM, bucket policy, and ACL. When the bucket's
// owner account cannot be determined the check falls to the same-account (union)
// rule, exactly as the Python does.
func (e *S3Evaluator) EvaluateS3Access(principalArn, action, resourceArn string) S3AccessCheckResult {
	bucketName, ok := parseS3BucketName(resourceArn)
	if !ok {
		return S3AccessCheckResult{Allowed: false}
	}
	bucketArn := "arn:aws:s3:::" + bucketName

	principalAccount, principalOK := accountIDFromARN(principalArn)
	bucketAccount := e.inferBucketAccount(bucketArn)
	isCrossAccount := principalOK && bucketAccount != "" && principalAccount != bucketAccount

	// Step 1: explicit deny from IAM policies.
	iamResult := e.checkIAMPolicies(principalArn, action, resourceArn)
	if iamResult.denied {
		return S3AccessCheckResult{Allowed: false, Denied: true, DenySource: "iam_policy"}
	}

	// Step 2: explicit deny from the bucket policy.
	bucketPolicyResult := e.checkBucketPolicy(bucketArn, principalArn, action, resourceArn)
	if bucketPolicyResult.denied {
		return S3AccessCheckResult{Allowed: false, Denied: true, DenySource: "bucket_policy"}
	}

	// Step 3: Block Public Access acts as an implicit deny for public access.
	if e.isBlockedByPublicAccess(bucketArn, action, principalArn) {
		return S3AccessCheckResult{Allowed: false, Denied: true, DenySource: "block_public_access"}
	}

	// Step 4: allows.
	iamAllowed := iamResult.allowed
	bucketPolicyAllowed := bucketPolicyResult.allowed
	aclAllowed := e.checkACL(action, resourceArn, bucketArn)

	// Step 5: combine per the S3 access rules.
	var allowSources []string
	var conditions []map[string]any
	var allowed bool
	if isCrossAccount {
		// Cross-account: BOTH IAM AND bucket policy must allow (an ACL grant can
		// independently grant access).
		if iamAllowed && bucketPolicyAllowed {
			allowed = true
			allowSources = append(allowSources, "iam_policy", "bucket_policy")
			conditions = append(conditions, iamResult.conditions...)
			conditions = append(conditions, bucketPolicyResult.conditions...)
		} else if aclAllowed {
			allowed = true
			allowSources = append(allowSources, "acl")
		} else {
			allowed = false
		}
	} else {
		// Same-account: IAM OR bucket policy OR ACL can grant.
		if iamAllowed {
			allowSources = append(allowSources, "iam_policy")
			conditions = append(conditions, iamResult.conditions...)
		}
		if bucketPolicyAllowed {
			allowSources = append(allowSources, "bucket_policy")
			conditions = append(conditions, bucketPolicyResult.conditions...)
		}
		if aclAllowed {
			allowSources = append(allowSources, "acl")
		}
		allowed = iamAllowed || bucketPolicyAllowed || aclAllowed
	}

	return S3AccessCheckResult{
		Allowed:              allowed,
		IAMAllowed:           iamAllowed,
		BucketPolicyAllowed:  bucketPolicyAllowed,
		ACLAllowed:           aclAllowed,
		AllowSources:         allowSources,
		Conditions:           conditions,
		HasConditions:        len(conditions) > 0,
		RequiresBucketPolicy: isCrossAccount && !aclAllowed,
	}
}

// checkIAMPolicies delegates to the identity side. Ported from
// S3PolicyEvaluator._check_iam_policies.
func (e *S3Evaluator) checkIAMPolicies(principalArn, action, resourceArn string) policyDecision {
	res := e.identity.CanPerformAction(principalArn, action, resourceArn)
	return policyDecision{allowed: res.Allowed, denied: res.Denied, conditions: res.Conditions}
}

// checkBucketPolicy evaluates the bucket policy for an allow/deny on
// (principal, action, resource). Ported from _s3_bucket_policy.check_bucket_policy.
//
// Bucket-policy evaluation follows the same per-statement matching + tri-state
// bias rules as identity policies (routed through ResolveMatchedStatements); only
// the principal match differs — bucket policies carry first-class Principal /
// NotPrincipal blocks. Policy variables in Resource / NotResource are substituted
// only when the policy language version is 2012-10-17.
func (e *S3Evaluator) checkBucketPolicy(bucketArn, principalArn, action, resourceArn string) policyDecision {
	config := e.bucketConfigs[bucketArn]
	if config == nil || config.BucketPolicy == nil {
		return policyDecision{}
	}
	policyDoc := config.BucketPolicy
	variablesEnabled := policyDoc.Version == "2012-10-17"

	getCtx := newContextMemo(e.contextBuilder, principalArn, action, resourceArn)
	matchResource := func(pattern string) bool {
		if variablesEnabled && HasPolicyVariables(pattern) {
			resolved, ok := ResolvePolicyVariables(pattern, getCtx(), true)
			if !ok {
				// An unresolved variable matches no concrete resource (Python's
				// resolve_policy_variables -> None -> resource_matches(None) False).
				return false
			}
			pattern = resolved
		}
		return resourceMatches(pattern, resourceArn)
	}

	var matchedAllows, matchedDenies []MatchedStatement
	for idx := range policyDoc.Statements {
		st := &policyDoc.Statements[idx]
		effect := st.Effect
		if effect != "Allow" && effect != "Deny" {
			continue
		}
		if !anyActionMatches(st.Action, action) {
			continue
		}

		// Resource, then (only if unmatched) NotResource — a present, non-empty
		// NotResource matches when the target is on none of its patterns.
		resourceMatch := false
		for _, r := range st.Resource {
			if matchResource(r) {
				resourceMatch = true
				break
			}
		}
		if !resourceMatch && len(st.NotResource) > 0 {
			excluded := false
			for _, r := range st.NotResource {
				if matchResource(r) {
					excluded = true
					break
				}
			}
			resourceMatch = !excluded
		}
		if !resourceMatch {
			continue
		}

		// Principal / NotPrincipal — a statement with neither is skipped.
		principalBlock := st.Principal
		notPrincipalBlock := st.NotPrincipal
		if principalBlock == nil && notPrincipalBlock == nil {
			continue
		}
		principalMatch := false
		if principalBlock != nil {
			principalMatch = principalBlockMatches(principalBlock, principalArn)
		}
		if !principalMatch && notPrincipalBlock != nil {
			principalMatch = !principalBlockMatches(notPrincipalBlock, principalArn)
		}
		if !principalMatch {
			continue
		}
		selected, state := selectStatementCondition(st.Condition, getCtx)
		if state == statementConditionKnownFalse {
			continue
		}
		ms := MatchedStatement{Condition: selected, Source: "bucket-policy/" + strconv.Itoa(idx)}
		if effect == "Allow" {
			matchedAllows = append(matchedAllows, ms)
		} else {
			matchedDenies = append(matchedDenies, ms)
		}
	}

	if len(matchedAllows) == 0 && len(matchedDenies) == 0 {
		return policyDecision{}
	}
	resolution := ResolveMatchedStatements(matchedAllows, matchedDenies, getCtx)
	return policyDecision{
		allowed:    resolution.Allowed,
		denied:     resolution.Denied,
		conditions: resolution.Conditions,
	}
}

// BucketPolicyMayAllowAny reports whether the bucket policy contains an Allow
// that names principalArn and at least one action of interest. Resource patterns
// and conditions are deliberately left to EvaluateS3Access: ignoring them here
// makes this a conservative bucket-level pre-filter while avoiding expansion to
// hundreds of thousands of object targets when a policy cannot name the
// principal at all.
func (e *S3Evaluator) BucketPolicyMayAllowAny(bucketArn, principalArn string, actions []string) bool {
	return e.BucketPolicyMayAllowMask(bucketArn, principalArn, actions) != 0
}

// BucketPolicyMayAllowMask is BucketPolicyMayAllowAny with one bit per input
// action, allowing the S3 builder to avoid evaluating action families that no
// bucket-policy statement can possibly grant.
func (e *S3Evaluator) BucketPolicyMayAllowMask(bucketArn, principalArn string, actions []string) uint64 {
	if len(actions) > 64 {
		panic("eval: action mask supports at most 64 actions")
	}
	config := e.bucketConfigs[bucketArn]
	if config == nil || config.BucketPolicy == nil {
		return 0
	}
	actionForContext := ""
	if len(actions) > 0 {
		actionForContext = actions[0]
	}
	getCtx := newContextMemo(e.contextBuilder, principalArn, actionForContext, bucketArn)
	var mask uint64
	for i := range config.BucketPolicy.Statements {
		st := &config.BucketPolicy.Statements[i]
		if st.Effect != "Allow" {
			continue
		}
		var actionMask uint64
		for i, action := range actions {
			if anyActionMatches(st.Action, action) {
				actionMask |= uint64(1) << i
			}
		}
		if actionMask == 0 {
			continue
		}
		principalMatches := st.Principal != nil && principalBlockMatches(st.Principal, principalArn)
		if !principalMatches && st.NotPrincipal != nil {
			principalMatches = !principalBlockMatches(st.NotPrincipal, principalArn)
		}
		if !principalMatches {
			continue
		}
		_, conditionState := selectStatementCondition(st.Condition, getCtx)
		if conditionState == statementConditionKnownFalse {
			continue
		}
		mask |= actionMask
	}
	return mask
}

// selectStatementCondition keeps condition keys the tensor can resolve and
// drops a bucket-policy hint only when that supported subset is known FALSE.
// Unsupported service-specific keys stay provisional until bounded source/
// resource analysis rather than automatically granting an edge.
type statementConditionState uint8

const (
	statementConditionNoUsable statementConditionState = iota
	statementConditionResolved
	statementConditionKnownFalse
)

func selectStatementCondition(condition Condition, getCtx ContextFactory) (Condition, statementConditionState) {
	var supported Condition
	for operator, kv := range condition {
		opLower := strings.ToLower(operator)
		if strings.Contains(opLower, "notequivalent") || strings.Contains(opLower, "setoperator") {
			continue
		}
		for key, values := range kv {
			keyLower := strings.ToLower(key)
			if !supportedConditionKey(keyLower) {
				continue
			}
			// A value-side policy variable may depend on a resource/request key even
			// though the condition key is principal-only. Leave those statements
			// conservative until the full check.
			variableDependent := false
			for _, value := range values {
				if strings.Contains(value, "${") {
					variableDependent = true
					break
				}
			}
			if variableDependent {
				continue
			}
			if supported == nil {
				supported = make(Condition)
			}
			if supported[operator] == nil {
				supported[operator] = make(map[string][]string)
			}
			supported[operator][key] = values
		}
	}
	if len(supported) == 0 {
		return condition, statementConditionNoUsable
	}
	if ResolveCondition(supported, getCtx()) == ResolutionFalse {
		return nil, statementConditionKnownFalse
	}
	return supported, statementConditionResolved
}

func supportedConditionKey(key string) bool {
	if strings.HasPrefix(key, "aws:principaltag/") {
		return true
	}
	switch key {
	case "aws:principalaccount", "aws:principalarn", "aws:principaltype",
		"aws:username", "aws:userid", "aws:principalorgid", "aws:principalorgpaths",
		"aws:resourceaccount", "s3:resourceaccount", "aws:requestedregion":
		return true
	}
	return false
}

// BucketACLMayAllowAny reports whether one of the public ACL grants that the
// evaluator recognizes can allow an action of interest. It folds in ownership
// controls and IgnorePublicAcls, so ordinary owner-only ACL metadata does not
// force every org principal through every bucket/object check.
func (e *S3Evaluator) BucketACLMayAllowAny(bucketArn string, actions []string) bool {
	return e.BucketACLMayAllowMask(bucketArn, actions) != 0
}

// BucketACLMayAllowMask is BucketACLMayAllowAny with one bit per input action.
func (e *S3Evaluator) BucketACLMayAllowMask(bucketArn string, actions []string) uint64 {
	if len(actions) > 64 {
		panic("eval: action mask supports at most 64 actions")
	}
	var mask uint64
	for i, action := range actions {
		if e.checkACL(action, bucketArn, bucketArn) {
			mask |= uint64(1) << i
		}
	}
	return mask
}

// CrossAccountAccessAlwaysBlocked reports the principal-independent branch of
// RestrictPublicBuckets. EvaluateS3Access returns this denial before composing
// either bucket policy or ACL allows, so a cross-account target can be removed
// without losing an edge.
func (e *S3Evaluator) CrossAccountAccessAlwaysBlocked(bucketArn string) bool {
	config := e.bucketConfigs[bucketArn]
	return config != nil && e.effectiveBPA(bucketArn).RestrictPublicBuckets && hasPublicPolicy(config)
}

// checkACL reports whether the bucket ACL grants action. Ported from
// _s3_acl.check_acl.
//
// Returns false when the bucket has BucketOwnerEnforced ownership (ACLs are
// disabled), when no ACL exists, when the action maps to no ACL permission level,
// or when no matching grant exists. Only AllUsers / AuthenticatedUsers group
// grants match, and only when IgnorePublicAcls is not in effect.
//
// CanonicalUser grantees are ignored: the Python matched them against a
// canonical-user id its resolver (_get_canonical_user_id) always left unresolved,
// so such a grant could never grant — the principal that only that dead path
// consulted is therefore not a parameter here. resourceArn is retained solely for
// the object-level-ACL lookup the Python had and this port omits (see
// S3Evaluator); it is unused today.
func (e *S3Evaluator) checkACL(action, resourceArn, bucketArn string) bool {
	config := e.bucketConfigs[bucketArn]
	if config != nil && config.OwnershipControls == "BucketOwnerEnforced" {
		return false
	}
	var acl *S3ACL
	if config != nil {
		acl = config.ACL
	}
	if acl == nil {
		return false
	}
	requiredPermission, ok := actionToACLPermission[action]
	if !ok {
		return false
	}
	ignorePublicACLs := e.effectiveBPA(bucketArn).IgnorePublicAcls

	for _, grant := range acl.Grants {
		// Only AllUsers / AuthenticatedUsers group grantees can grant; every other
		// grantee kind (CanonicalUser, …) is ignored.
		if grant.Grantee.Type != "Group" {
			continue
		}
		uri := grant.Grantee.URI
		if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
			if ignorePublicACLs {
				continue
			}
			if grant.Permission == requiredPermission || grant.Permission == "FULL_CONTROL" {
				return true
			}
		}
	}
	return false
}

// isBlockedByPublicAccess reports whether Block Public Access blocks this request.
// Ported from S3PolicyEvaluator._is_blocked_by_public_access: RestrictPublicBuckets
// blocks a cross-account principal on a bucket whose policy is public (any Allow
// statement with Principal "*"); same-account principals are exempt. The action is
// not consulted (kept for signature parity with the Python).
func (e *S3Evaluator) isBlockedByPublicAccess(bucketArn, action, principalArn string) bool {
	config := e.bucketConfigs[bucketArn]
	if config == nil {
		return false
	}
	settings := e.effectiveBPA(bucketArn)
	if settings.RestrictPublicBuckets && hasPublicPolicy(config) {
		principalAccount, ok := accountIDFromARN(principalArn)
		if ok && config.OwnerAccountID != "" && principalAccount != config.OwnerAccountID {
			return true
		}
	}
	return false
}

// effectiveBPA merges the bucket-level and account-level Block Public Access
// settings with boolean OR (most restrictive wins). Ported from
// S3PolicyEvaluator._get_effective_bpa.
func (e *S3Evaluator) effectiveBPA(bucketArn string) PublicAccessBlock {
	config := e.bucketConfigs[bucketArn]
	var bucketBPA PublicAccessBlock
	if config != nil && config.BlockPublicAccess != nil {
		bucketBPA = *config.BlockPublicAccess
	}
	var accountBPA PublicAccessBlock
	if config != nil && config.OwnerAccountID != "" {
		if a := e.accountPublicAccessBlocks[config.OwnerAccountID]; a != nil {
			accountBPA = *a
		}
	}
	return PublicAccessBlock{
		BlockPublicAcls:       bucketBPA.BlockPublicAcls || accountBPA.BlockPublicAcls,
		IgnorePublicAcls:      bucketBPA.IgnorePublicAcls || accountBPA.IgnorePublicAcls,
		BlockPublicPolicy:     bucketBPA.BlockPublicPolicy || accountBPA.BlockPublicPolicy,
		RestrictPublicBuckets: bucketBPA.RestrictPublicBuckets || accountBPA.RestrictPublicBuckets,
	}
}

// inferBucketAccount returns the bucket owner's account, or "" when unknown.
// Ported from S3PolicyEvaluator._infer_bucket_account: the owner account carried
// on the config (which the runtime always populates with the account the bucket
// was collected from). The Python "_owner_account" bucket-policy-metadata fallback
// applied only to the deprecated dict path and is dead under the config wiring, so
// it is omitted.
func (e *S3Evaluator) inferBucketAccount(bucketArn string) string {
	config := e.bucketConfigs[bucketArn]
	if config == nil {
		return ""
	}
	return config.OwnerAccountID
}

// hasPublicPolicy reports whether a bucket policy has a public allow statement
// (any Allow whose Principal is "*", or whose Principal.AWS contains "*"). Ported
// from S3PolicyEvaluator._has_public_policy.
func hasPublicPolicy(config *S3BucketConfig) bool {
	if config.BucketPolicy == nil {
		return false
	}
	for i := range config.BucketPolicy.Statements {
		st := &config.BucketPolicy.Statements[i]
		if st.Effect != "Allow" {
			continue
		}
		p := st.Principal
		if p == nil {
			continue
		}
		if p.Wildcard {
			return true
		}
		for _, a := range p.AWS {
			if a == "*" {
				return true
			}
		}
	}
	return false
}

// parseS3BucketName extracts the bucket name from an S3 resource ARN
// (arn:aws:s3:::bucket or arn:aws:s3:::bucket/key…). Ported from
// s3_policy_evaluator._parse_s3_arn (the object key is discarded — the evaluator
// only needs the bucket name). ok is false for a non-S3 or empty-resource ARN.
func parseS3BucketName(arn string) (string, bool) {
	const prefix = "arn:aws:s3:::"
	if !strings.HasPrefix(arn, prefix) {
		return "", false
	}
	resourcePart := arn[len(prefix):]
	if resourcePart == "" {
		return "", false
	}
	if i := strings.IndexByte(resourcePart, '/'); i >= 0 {
		return resourcePart[:i], true
	}
	return resourcePart, true
}
