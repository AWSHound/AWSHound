package eval

import (
	"strings"

	"github.com/AWSHound/AWSHound/internal/model"
)

// This file builds the request context that condition resolution reads. It ports
// account_data.get_policy_variable_context (query-time principal/resource
// metadata plus org keys) and conditions/cache_build_resolution.py (the
// account-scoped context and the partial pre-resolution applied when the
// per-principal permission cache is built).

// -------------------------------------------------------------------------
// Cache-build partial resolution (conditions/cache_build_resolution.py)
// -------------------------------------------------------------------------

// accountScopedKeys are the condition keys derivable purely from a principal's
// fingerprint inputs, so a condition over only these is safe to pre-resolve at
// cache build. Ported from cache_build_resolution._ACCOUNT_SCOPED_KEYS.
var accountScopedKeys = map[string]bool{
	"aws:principalaccount":  true,
	"aws:principalorgid":    true,
	"aws:principalorgpaths": true,
}

type cacheOutcome int

const (
	cacheKeep  cacheOutcome = iota // keep verbatim for query-time resolution
	cacheStrip                     // resolved TRUE -> keep with condition cleared
	cacheDrop                      // resolved FALSE under bias -> remove
)

// applyCacheBuildFilter pre-resolves account-scoped conditions in the compressed
// permissions using an account-only context. Ported from
// account_data.get_permissions' filter_statements_inplace calls. This makes the
// cache entry independent of whether the query-time ctx carries account/org keys.
func (pe *PolicyEvaluator) applyCacheBuildFilter(cp *compressedPermissions, accountID string) {
	od := pe.orgDataOnce()
	ctx := buildAccountScopedContext(accountID, pe.orgIDForAccount(accountID), od.orgPathForAccount(accountID))
	filterStatementsInPlace(cp.allowByAction, ctx, EffectAllow)
	filterStatementsInPlace(cp.denyByAction, ctx, EffectDeny)
}

// buildAccountScopedContext builds a RequestContext holding only fingerprint-
// stable values; all identity/resource keys resolve UNKNOWN (the *Known flags
// are false). Ported from cache_build_resolution.build_account_scoped_context.
func buildAccountScopedContext(principalAccount, orgID, orgPaths string) *RequestContext {
	values := map[string]string{"aws:principalaccount": principalAccount}
	if orgID != "" {
		values["aws:principalorgid"] = orgID
	}
	if orgPaths != "" {
		values["aws:principalorgpaths"] = orgPaths
	}
	return &RequestContext{
		Values:         values,
		PrincipalTags:  map[string]string{},
		ResourceTags:   map[string]string{},
		PrincipalKnown: false,
		ResourceKnown:  false,
		OrgDataKnown:   orgID != "" || orgPaths != "",
	}
}

// isAccountScopedCondition reports whether every condition key is account-scoped.
// Ported from cache_build_resolution.is_account_scoped_condition.
func isAccountScopedCondition(cond Condition) bool {
	if len(cond) == 0 {
		return false
	}
	for _, block := range cond {
		for key := range block {
			if !accountScopedKeys[strings.ToLower(key)] {
				return false
			}
		}
	}
	return true
}

// filterStatementsInPlace applies cache-build resolution to every logical
// statement before lazy action views are published. DROP removes a statement,
// STRIP clears its condition, and KEEP leaves it verbatim.
func filterStatementsInPlace(index *compressedIndex, ctx *RequestContext, effect Effect) {
	if index == nil {
		return
	}
	kept := make([]*compressedStatement, 0, len(index.statements))
	for _, s := range index.statements {
		switch outcome, repl := resolveAtCacheBuild(s, ctx, effect); outcome {
		case cacheDrop:
			// skip
		case cacheStrip:
			kept = append(kept, repl)
		default:
			kept = append(kept, s)
		}
	}
	index.statements = kept
}

// resolveAtCacheBuild decides a statement's fate at cache build. Ported from
// cache_build_resolution.resolve_at_cache_build. A condition-free statement is
// already clean (kept as-is); a non-account-scoped or UNKNOWN condition is kept
// verbatim; an account-scoped condition resolving FALSE under attacker bias is
// dropped and one resolving TRUE is stripped to a condition-free copy.
func resolveAtCacheBuild(s *compressedStatement, ctx *RequestContext, effect Effect) (cacheOutcome, *compressedStatement) {
	if len(s.condition) == 0 {
		return cacheStrip, s // already clean; no copy needed.
	}
	if !isAccountScopedCondition(s.condition) {
		return cacheKeep, s
	}
	switch ApplyConditionBias(effect, ResolveCondition(s.condition, ctx)) {
	case BiasDiscard:
		return cacheDrop, nil
	case BiasRetainClean:
		return cacheStrip, stripCondition(s)
	default: // BiasRetainConditional (defensive; account-scoped never UNKNOWN with full account ctx)
		return cacheKeep, s
	}
}

// stripCondition returns a shallow copy of s with its condition cleared. The
// shared bitmaps/patterns are read-only, so aliasing them is safe. Ported from
// cache_build_resolution._strip_condition.
func stripCondition(s *compressedStatement) *compressedStatement {
	c := *s
	c.condition = nil
	return &c
}

// -------------------------------------------------------------------------
// Policy-variable request context (account_data.get_policy_variable_context)
// -------------------------------------------------------------------------

// principalMeta is the slice of a principal's collected IAM metadata the context
// builder needs: its tags and (for users) the UserName/UserId that back
// aws:username / aws:userid. A nil *principalMeta means the ARN is not a known
// user/role/group in the store (PrincipalKnown=false).
type principalMeta struct {
	tags     []model.Tag
	userName string
	userID   string
}

// resourceMeta is the slice of a resource's collected metadata the context
// builder reads: its account, region, and tags. A nil *resourceMeta means the
// ARN is not a known resource (ResourceKnown=false). Fields are "" / nil when the
// collected metadata does not carry them (an IAM principal or managed-policy blob
// has no AccountId/Region), so those keys stay unset exactly as in
// get_policy_variable_context.
type resourceMeta struct {
	accountID string
	region    string
	tags      []model.Tag
}

// principalMetadata returns the collected IAM metadata for a user/role/group ARN,
// or nil when the ARN is not a known principal. Ported from
// account_data.get_principal_metadata; the ARN embeds its account, so the lookup
// is account-scoped (equivalent to the Python global principal snapshot for
// well-formed ARNs).
func (pe *PolicyEvaluator) principalMetadata(arn string) *principalMeta {
	accountID, ok := accountIDFromARN(arn)
	if !ok {
		return nil
	}
	acct, ok := pe.account(accountID)
	if !ok {
		return nil
	}
	if u := acct.Users[arn]; u != nil {
		return &principalMeta{tags: u.Tags, userName: u.UserName, userID: u.UserId}
	}
	if r := acct.Roles[arn]; r != nil {
		return &principalMeta{tags: r.Tags}
	}
	if g := acct.Groups[arn]; g != nil {
		return &principalMeta{} // groups carry no tags / username / userid
	}
	return nil
}

// resourceMetadata returns the collected metadata for a resource ARN, or nil when
// the ARN is not a known resource. Ported from
// account_data.get_resource_metadata / _get_resource_metadata_uncached, covering
// the resource kinds this evaluator resolves conditions against: IAM principals,
// managed policies, S3 buckets/objects, and the non-IAM/non-S3 service resources
// (KMS, EC2, Lambda, SSM, EKS, CloudFormation) whose aws:ResourceTag/* conditions
// gate real attack-path edges. For those service resources only tags and the
// ResourceKnown flag are added — account/region derive from the ARN identically to
// the prior nil-resource path, so no other resolved value changes — and only
// resources whose tags were actually collected are known (ABSENT vs UNKNOWN;
// see store.ResourceTagsByArn).
//
// Field presence otherwise mirrors the Python dict shapes: an IAM principal or
// managed-policy blob carries no AccountId/Region (so those keys stay unset even
// though the ARN has them), while the S3 metadata explicitly carries the bucket's
// account/region/tags.
func (pe *PolicyEvaluator) resourceMetadata(arn string) *resourceMeta {
	if p := pe.principalMetadata(arn); p != nil {
		return &resourceMeta{tags: p.tags}
	}
	pe.ensureManaged()
	if _, ok := pe.managedByArn[arn]; ok {
		return &resourceMeta{}
	}
	if m := pe.s3ResourceMetadata(arn); m != nil {
		return m
	}
	pe.ensureResourceTags()
	if tags, ok := pe.resTagsByArn[arn]; ok {
		acct, _ := accountIDFromARN(arn)
		return &resourceMeta{accountID: acct, region: regionFromArn(arn), tags: tags}
	}
	return nil
}

// ensureResourceTags builds the ARN -> tags index for non-IAM/non-S3 service
// resources once, merging every account's ResourceTagsByArn. First ARN wins on the
// (not expected) chance of a collision, matching the other scan-once indexes.
func (pe *PolicyEvaluator) ensureResourceTags() {
	pe.resTagsOnce.Do(func() {
		m := map[string][]model.Tag{}
		for _, a := range pe.store.Accounts() {
			for arn, tags := range a.ResourceTagsByArn() {
				if _, exists := m[arn]; !exists {
					m[arn] = tags
				}
			}
		}
		pe.resTagsByArn = m
	})
}

// s3ResourceMetadata resolves an S3 bucket/object ARN to its metadata. Ported
// from account_data._get_s3_resource_metadata: an unknown bucket is nil; a bucket
// ARN carries the bucket's account/region/tags; an object ARN carries only the
// bucket's account (Region/Tags are not part of the object dict).
func (pe *PolicyEvaluator) s3ResourceMetadata(arn string) *resourceMeta {
	const prefix = "arn:aws:s3:::"
	bucketName, ok := parseS3BucketName(arn)
	if !ok {
		return nil
	}
	pe.ensureS3()
	bucket, ok := pe.s3ByName[bucketName]
	if !ok {
		return nil
	}
	// An object ARN (a non-empty key after the bucket name) carries only the
	// bucket's account; a bare bucket ARN carries the full bucket metadata.
	objectKey := ""
	if i := strings.IndexByte(arn[len(prefix):], '/'); i >= 0 {
		objectKey = arn[len(prefix)+i+1:]
	}
	if objectKey == "" {
		return bucket
	}
	return &resourceMeta{accountID: bucket.accountID}
}

// ensureS3 builds the bucket-name -> metadata index once. Bucket names are
// globally unique in AWS, so a name maps to a single bucket; the first wins on the
// (test-only) chance of a collision. Mirrors _get_s3_resource_metadata's lookup of
// the s3_bucket table by name.
func (pe *PolicyEvaluator) ensureS3() {
	pe.s3Once.Do(func() {
		m := make(map[string]*resourceMeta)
		for _, a := range pe.store.Accounts() {
			for _, b := range a.S3BucketList() {
				if b.Name == "" {
					continue
				}
				if _, exists := m[b.Name]; !exists {
					m[b.Name] = &resourceMeta{accountID: a.ID, region: b.Region, tags: b.Tags}
				}
			}
		}
		pe.s3ByName = m
	})
}

// buildPolicyVarContext builds the store-backed request context for one
// (principal, action, resource) authorization check. Ported field-for-field from
// account_data.get_policy_variable_context. action is part of the conceptual
// request signature but affects no produced value (kept for symmetry with the
// Python). It sets aws:principalarn always; the account / region / type /
// username / userid / org-id / org-paths keys derivable from the store; the
// principal and resource tag maps; and the *Known flags that drive tri-state key
// resolution.
func (pe *PolicyEvaluator) buildPolicyVarContext(principalArn, action, resourceArn string) *RequestContext {
	principal := pe.principalMetadata(principalArn)
	resource := pe.resourceMetadata(resourceArn)

	principalAccount, _ := accountIDFromARN(principalArn)
	var resourceAccount, resourceRegion string
	if resource != nil {
		resourceAccount = resource.accountID
		resourceRegion = resource.region
	} else {
		resourceAccount, _ = accountIDFromARN(resourceArn)
		resourceRegion = regionFromArn(resourceArn)
	}

	values := map[string]string{"aws:principalarn": principalArn}
	if principalAccount != "" {
		values["aws:principalaccount"] = principalAccount
	}
	if resourceAccount != "" {
		values["aws:resourceaccount"] = resourceAccount
	}
	if strings.HasPrefix(resourceArn, "arn:aws:s3:::") && resourceAccount != "" {
		values["s3:resourceaccount"] = resourceAccount
	}
	if resourceRegion != "" {
		values["aws:requestedregion"] = resourceRegion
	}

	principalType := principalTypeFromMetadata(principalArn, principal)
	if principalType != "" {
		values["aws:principaltype"] = principalType
	}
	if principal != nil && principalType == "IAMUser" {
		if principal.userName != "" {
			values["aws:username"] = principal.userName
		}
		if principal.userID != "" {
			values["aws:userid"] = principal.userID
		}
	}

	if orgID := pe.orgIDForAccount(principalAccount); orgID != "" {
		values["aws:principalorgid"] = orgID
	}
	if orgID := pe.orgIDForAccount(resourceAccount); orgID != "" {
		values["aws:resourceorgid"] = orgID
	}
	od := pe.orgDataOnce()
	if paths := od.orgPathForAccount(principalAccount); paths != "" {
		values["aws:principalorgpaths"] = paths
	}
	if paths := od.orgPathForAccount(resourceAccount); paths != "" {
		values["aws:resourceorgpaths"] = paths
	}

	var principalTags, resourceTags []model.Tag
	if principal != nil {
		principalTags = principal.tags
	}
	if resource != nil {
		resourceTags = resource.tags
	}

	return &RequestContext{
		Values:         values,
		PrincipalTags:  normalizeTags(principalTags),
		ResourceTags:   normalizeTags(resourceTags),
		PrincipalKnown: principal != nil,
		ResourceKnown:  resource != nil,
		OrgDataKnown:   od.hasOrg,
	}
}

// ResourcePolicyContext exposes the same store-backed request context used by
// CanPerformAction to the S3/Lambda resource-policy evaluators. Resource-policy
// conditions must not fall back to UNKNOWN merely because those evaluators use
// the IdentityEvaluator adapter rather than calling CanPerformAction directly.
func (pe *PolicyEvaluator) ResourcePolicyContext(principalArn, action, resourceArn string) *RequestContext {
	return pe.buildPolicyVarContext(principalArn, action, resourceArn)
}

// principalTypeFromMetadata returns the AWS-style aws:PrincipalType for a
// principal ARN. Ported from account_data._principal_type_from_metadata: a
// ":root" ARN is always "Account"; otherwise an unknown principal has no type,
// and a known one maps ":user/" -> IAMUser, ":role/" -> AssumedRole,
// ":group/" -> Group.
func principalTypeFromMetadata(principalArn string, principal *principalMeta) string {
	if strings.HasSuffix(principalArn, ":root") {
		return "Account"
	}
	if principal == nil {
		return ""
	}
	switch {
	case strings.Contains(principalArn, ":user/"):
		return "IAMUser"
	case strings.Contains(principalArn, ":role/"):
		return "AssumedRole"
	case strings.Contains(principalArn, ":group/"):
		return "Group"
	}
	return ""
}

// regionFromArn returns the region field (index 3) of an ARN, or "" when absent.
// Ported from account_data._extract_region_from_arn.
func regionFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 && parts[3] != "" {
		return parts[3]
	}
	return ""
}

// normalizeTags flattens a collected tag list to {key: value}. Ported from
// policy_variables.normalize_tags (the list-of-{Key,Value} shape); the returned
// map is always non-nil, matching normalize_tags(None) -> {}.
func normalizeTags(tags []model.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[t.Key] = t.Value
	}
	return out
}

// overlayContext returns base with the caller overlay's Values and KnownKeys
// (lower-cased) merged on top; the tag maps and *Known flags are inherited from
// base unchanged. A nil/empty overlay returns base as-is. Ported from can_perform_action's
// per-call request_context merge (dataclasses.replace(base, values={**base,
// **overlay})), which keeps the shared per-pair base context uncontaminated.
func overlayContext(base, overlay *RequestContext) *RequestContext {
	if overlay == nil || (len(overlay.Values) == 0 && len(overlay.KnownKeys) == 0) {
		return base
	}
	merged := make(map[string]string, len(base.Values)+len(overlay.Values))
	for k, v := range base.Values {
		merged[k] = v
	}
	for k, v := range overlay.Values {
		merged[strings.ToLower(k)] = v
	}
	knownKeys := make(map[string]bool, len(base.KnownKeys)+len(overlay.KnownKeys))
	for k, known := range base.KnownKeys {
		knownKeys[k] = known
	}
	for k, known := range overlay.KnownKeys {
		knownKeys[strings.ToLower(k)] = known
	}
	return &RequestContext{
		Values:         merged,
		KnownKeys:      knownKeys,
		PrincipalTags:  base.PrincipalTags,
		ResourceTags:   base.ResourceTags,
		PrincipalKnown: base.PrincipalKnown,
		ResourceKnown:  base.ResourceKnown,
		OrgDataKnown:   base.OrgDataKnown,
	}
}
