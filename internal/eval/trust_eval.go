package eval

import (
	"regexp"
	"strings"
	"sync"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/AWSHound/AWSHound/internal/model"
)

// This file answers "does role R's trust policy admit principal P?". It ports the
// trust path of policy_evaluator.py (the principal trust-state index, the
// bitmap-accelerated check_trust_policy, role_trust_bm and principal-entry
// resolution) together with the ARN wildcard-pattern matchers from trust_policy.py
// (arn_pattern_to_regex, resource_matches).

// -------------------------------------------------------------------------
// Trust policy (policy_evaluator trust path + trust_evaluator/trust_policy)
// -------------------------------------------------------------------------

// principalRef pairs a principal ARN with its shared ArnIndex int-id.
type principalRef struct {
	arn string
	id  uint32
}

// trustState is the principal int index used to accelerate trust checks: the
// universal principal bitmap, per-account principal bitmaps, and the list of
// (arn, id) pairs for wildcard regex matching. Ported from
// policy_evaluator._ensure_trust_state, but keyed on the SHARED ArnIndex ids so
// the bitmaps interoperate with PrincipalsWithAction and callers. "Principals"
// are users + roles (matching iter_principal_arns); groups are excluded.
type trustState struct {
	universalPrincipalBM  *roaring.Bitmap
	principalsByAccountBM map[string]*roaring.Bitmap
	principalRefs         []principalRef
}

func (pe *PolicyEvaluator) ensureTrustState() *trustState {
	pe.trustOnce.Do(func() {
		ts := &trustState{
			universalPrincipalBM:  roaring.New(),
			principalsByAccountBM: map[string]*roaring.Bitmap{},
		}
		add := func(arn string) {
			id, ok := pe.arn.ID(arn)
			if !ok {
				return
			}
			ts.universalPrincipalBM.Add(id)
			ts.principalRefs = append(ts.principalRefs, principalRef{arn: arn, id: id})
			acct, _ := accountSegment(arn)
			bm := ts.principalsByAccountBM[acct]
			if bm == nil {
				bm = roaring.New()
				ts.principalsByAccountBM[acct] = bm
			}
			bm.Add(id)
		}
		for _, acct := range pe.store.Accounts() {
			for arn := range acct.Users {
				add(arn)
			}
			for arn := range acct.Roles {
				add(arn)
			}
		}
		pe.trustStateVal = ts
	})
	return pe.trustStateVal
}

// CheckTrustPolicy checks whether a role's trust policy admits a principal for
// sts:AssumeRole. Ported from policy_evaluator.check_trust_policy /
// _check_trust_policy_impl / trust_evaluator.evaluate_trust_doc.
//
// It is bitmap-accelerated: an interned principal absent from the role's trust
// bitmap (the set of principals the trust NAMES, ignoring conditions) is rejected
// immediately; otherwise the trust document is fully evaluated, with conditions
// resolved through the shared attacker-bias resolver. A non-interned principal
// (cross-account, not in the store) skips the bitmap and is evaluated directly by
// string/pattern matching.
func (pe *PolicyEvaluator) CheckTrustPolicy(role *model.RoleDetail, principalArn string, ctx *RequestContext) *TrustCheckResult {
	const action = "sts:AssumeRole"
	if role == nil {
		return &TrustCheckResult{Trusted: false}
	}
	if id, ok := pe.arn.ID(principalArn); ok {
		if !pe.roleTrustBM(role, action).Contains(id) {
			return &TrustCheckResult{Trusted: false}
		}
	}
	// Build the trust context from the assuming principal (as principal) and the
	// role (as resource), so trust-policy conditions on aws:PrincipalArn,
	// aws:PrincipalTag/*, aws:PrincipalOrgID, aws:PrincipalType, etc. resolve.
	// Mirrors _check_trust_policy_impl's get_policy_variable_context(principal=
	// target, resource=role). Built lazily — only when a matched trust statement
	// is conditioned. Any caller ctx overlays on top (callers currently pass nil).
	ctxFactory := func() *RequestContext {
		return overlayContext(pe.buildPolicyVarContext(principalArn, action, role.Arn), ctx)
	}
	// Trust documents from GetAccountAuthorizationDetails ARE url-encoded, so parse
	// via ParsePolicyDocument; a missing/unparsable document is not trusted. Then
	// hand off to the single trust-document walker (trust.go) with the canonical
	// AWS-principal matcher.
	doc, err := ParsePolicyDocument(role.AssumeRolePolicyDocument)
	if err != nil || doc == nil {
		return &TrustCheckResult{Trusted: false}
	}
	res := evaluateTrustDoc(doc, principalArn, action, TrustPrincipalMatches, ctxFactory)
	return &res
}

// RoleTrustBitmap returns a clone of the set of principal ARN int-ids that
// role's trust policy names for action (default sts:AssumeRole when action is
// ""). Public companion to PrincipalsWithAction for the bitmap-intersection
// pre-filter pattern; a clone is returned so the caller may mutate it (roaring
// And/Or mutate in place) without corrupting the cache. Ported from
// policy_evaluator.role_trust_bm.
func (pe *PolicyEvaluator) RoleTrustBitmap(role *model.RoleDetail, action string) *roaring.Bitmap {
	if action == "" {
		action = "sts:AssumeRole"
	}
	if role == nil {
		return roaring.New()
	}
	return pe.roleTrustBM(role, action).Clone()
}

// RoleDirectSameAccountTrustBitmap returns the known IAM users/roles that are
// named by exact ARN in an Allow statement in role's trust policy and belong to
// the role's account. Those direct grants are special in AWS: unlike a trust of
// the account root, they can authorize sts:AssumeRole without a second
// identity-policy Allow. Conditions and Deny statements are deliberately ignored
// in this candidate bitmap and are resolved before an edge is emitted.
func (pe *PolicyEvaluator) RoleDirectSameAccountTrustBitmap(role *model.RoleDetail, action string) *roaring.Bitmap {
	if action == "" {
		action = "sts:AssumeRole"
	}
	out := roaring.New()
	if role == nil {
		return out
	}
	roleAccount, ok := accountSegment(role.Arn)
	if !ok || roleAccount == "" {
		return out
	}
	ts := pe.ensureTrustState()
	doc, err := ParsePolicyDocument(role.AssumeRolePolicyDocument)
	if err != nil || doc == nil {
		return out
	}
	for i := range doc.Statements {
		st := &doc.Statements[i]
		if st.Effect != "Allow" || !trustStatementActionMatches(st, strings.ToLower(action)) || st.Principal == nil {
			continue
		}
		for _, principal := range st.Principal.AWS {
			if !directSameAccountIAMPrincipal(roleAccount, principal) {
				continue
			}
			if id, ok := pe.arn.ID(principal); ok && ts.universalPrincipalBM.Contains(id) {
				out.Add(id)
			}
		}
	}
	return out
}

// CheckDirectSameAccountTrustPolicy evaluates only exact same-account IAM
// principal ARN grants in role's trust policy. Account-root, wildcard and
// cross-account delegation are intentionally excluded: those require an
// identity-policy sts:AssumeRole Allow and are handled by CheckTrustPolicy.
func (pe *PolicyEvaluator) CheckDirectSameAccountTrustPolicy(role *model.RoleDetail, principalArn string, ctx *RequestContext) *TrustCheckResult {
	if role == nil {
		return &TrustCheckResult{Trusted: false}
	}
	roleAccount, roleOK := accountSegment(role.Arn)
	principalAccount, principalOK := accountSegment(principalArn)
	if !roleOK || !principalOK || roleAccount == "" || roleAccount != principalAccount ||
		!directSameAccountIAMPrincipal(roleAccount, principalArn) {
		return &TrustCheckResult{Trusted: false}
	}
	doc, err := ParsePolicyDocument(role.AssumeRolePolicyDocument)
	if err != nil || doc == nil {
		return &TrustCheckResult{Trusted: false}
	}
	ctxFactory := func() *RequestContext {
		return overlayContext(pe.buildPolicyVarContext(principalArn, "sts:AssumeRole", role.Arn), ctx)
	}
	exactPrincipal := func(p *Principal, target string) bool {
		if p == nil {
			return false
		}
		for _, entry := range p.AWS {
			if entry == target {
				return true
			}
		}
		return false
	}
	directAllowMatch := func(st *Statement, target string) bool {
		return st.Principal != nil && exactPrincipal(st.Principal, target)
	}
	directDenyMatch := func(st *Statement, target string) bool {
		return trustStatementPrincipalMatches(st, target, TrustPrincipalMatches)
	}
	res := evaluateTrustDocWithMatchers(doc, principalArn, "sts:AssumeRole", directAllowMatch, directDenyMatch, ctxFactory)
	return &res
}

func directSameAccountIAMPrincipal(accountID, arn string) bool {
	account, ok := accountSegment(arn)
	if !ok || account != accountID || strings.ContainsAny(arn, "*?") {
		return false
	}
	return strings.Contains(arn, ":iam::"+accountID+":user/") ||
		strings.Contains(arn, ":iam::"+accountID+":role/")
}

// roleTrustBM builds (and caches) the set of principal int-ids a role's trust
// policy names for action, ignoring conditions. Ported from
// policy_evaluator._get_role_trust_bm. The returned bitmap is shared and
// read-only; callers that mutate must clone (see RoleTrustBitmap).
func (pe *PolicyEvaluator) roleTrustBM(role *model.RoleDetail, action string) *roaring.Bitmap {
	cacheKey := role.Arn + "\x00" + action
	pe.trustBMMu.Lock()
	if bm, ok := pe.roleTrustCache[cacheKey]; ok {
		pe.trustBMMu.Unlock()
		return bm
	}
	pe.trustBMMu.Unlock()

	ts := pe.ensureTrustState()
	bm := roaring.New()
	if pol, err := ParsePolicyDocument(role.AssumeRolePolicyDocument); err == nil && pol != nil {
		actionLower := strings.ToLower(action)
		for i := range pol.Statements {
			st := &pol.Statements[i]
			if st.Effect != "Allow" || !trustStatementActionMatches(st, actionLower) {
				continue
			}
			block := st.Principal
			if block == nil {
				continue
			}
			if block.Wildcard {
				bm.Or(ts.universalPrincipalBM)
				continue
			}
			for _, entry := range block.AWS {
				bm.Or(pe.resolvePrincipalEntryToBM(entry, ts))
			}
		}
	}

	pe.trustBMMu.Lock()
	if existing, ok := pe.roleTrustCache[cacheKey]; ok {
		bm = existing
	} else {
		pe.roleTrustCache[cacheKey] = bm
	}
	pe.trustBMMu.Unlock()
	return bm
}

// resolvePrincipalEntryToBM resolves one Principal.AWS entry to a bitmap of
// principal int-ids. Ported from policy_evaluator._resolve_principal_entry_to_bm.
// The returned bitmap may be a shared trust-state bitmap (for "*" / account
// root); callers only Or it into a fresh accumulator, so sharing is safe.
func (pe *PolicyEvaluator) resolvePrincipalEntryToBM(entry string, ts *trustState) *roaring.Bitmap {
	if entry == "*" {
		return ts.universalPrincipalBM
	}
	if isDigits(entry) && len(entry) == 12 {
		entry = "arn:aws:iam::" + entry + ":root"
	}
	if strings.HasSuffix(entry, ":root") {
		if acct, ok := accountSegment(entry); ok {
			if bm, ok := ts.principalsByAccountBM[acct]; ok {
				return bm
			}
		}
		return roaring.New()
	}
	if strings.ContainsAny(entry, "*?") {
		re := arnPatternRegex(entry)
		bm := roaring.New()
		for _, p := range ts.principalRefs {
			if re.MatchString(p.arn) {
				bm.Add(p.id)
			}
		}
		return bm
	}
	// Exact ARN: a single bit iff it is a known principal (users/roles).
	if id, ok := pe.arn.ID(entry); ok && ts.universalPrincipalBM.Contains(id) {
		bm := roaring.New()
		bm.Add(id)
		return bm
	}
	return roaring.New()
}

// -------------------------------------------------------------------------
// ARN-pattern matching helpers (trust_policy.arn_pattern_to_regex / resource_matches)
// -------------------------------------------------------------------------

// arnRegexCache memoises compiled ARN-pattern regexes (the counterpart of
// trust_policy.arn_pattern_to_regex's lru_cache).
var arnRegexCache sync.Map // string -> *regexp.Regexp

// neverMatchRe never matches a non-empty ARN; used when a pattern fails to
// compile (a malformed policy pattern must not panic the build).
var neverMatchRe = regexp.MustCompile(`\A\z\A`)

// arnPatternRegex compiles an AWS IAM wildcard ARN pattern into an anchored
// regexp ("*" -> ".*", "?" -> ".", everything else escaped). Ported from
// trust_policy.arn_pattern_to_regex.
func arnPatternRegex(pattern string) *regexp.Regexp {
	if v, ok := arnRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	var b strings.Builder
	b.WriteByte('^')
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
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		re = neverMatchRe
	}
	arnRegexCache.Store(pattern, re)
	return re
}

// resourceMatches reports whether arn matches the IAM resource pattern. Ported
// from trust_policy.resource_matches: "*" always matches; otherwise a full
// (anchored) regex match.
func resourceMatches(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == arn
	}
	// The dominant IAM resource shapes are an exact ARN and ARN-prefix/*.
	// Handle the one-star forms without invoking regexp; the general anchored
	// matcher remains the source of truth for interior/multiple wildcards.
	if strings.Count(pattern, "*") == 1 && !strings.ContainsRune(pattern, '?') {
		if pattern[len(pattern)-1] == '*' {
			return strings.HasPrefix(arn, pattern[:len(pattern)-1])
		}
		if pattern[0] == '*' {
			return strings.HasSuffix(arn, pattern[1:])
		}
	}
	return arnPatternRegex(pattern).MatchString(arn)
}

// isDigits reports whether s is a non-empty run of ASCII digits (Python's
// str.isdigit for the account-id normalisation).
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
