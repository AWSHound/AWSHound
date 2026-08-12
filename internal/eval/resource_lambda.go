package eval

import (
	"strconv"
	"strings"
)

// This file ports AWSHound's Lambda resource-policy evaluator
// (core/evaluation/lambda_resource_policy_evaluator.py).
//
// Lambda uses a simpler model than S3: a service principal is authorized by the
// resource policy alone (IAM is not consulted); a same-account IAM principal is
// authorized by IAM OR the resource policy; a cross-account IAM principal needs
// IAM AND the resource policy; and an explicit deny on either layer wins.

// LambdaAccessCheckResult is the outcome of a Lambda access evaluation across IAM
// and the function resource policy. Ported field-for-field from
// lambda_resource_policy_evaluator.LambdaAccessCheckResult.
type LambdaAccessCheckResult struct {
	Allowed               bool
	IAMAllowed            bool
	ResourcePolicyAllowed bool
	Denied                bool
	DenySource            string
	AllowSources          []string
	Conditions            []map[string]any
	HasConditions         bool
}

// LambdaEvaluator evaluates Lambda access across IAM policies and function
// resource policies. Ported from
// lambda_resource_policy_evaluator.LambdaResourcePolicyEvaluator.
//
// It is read-only after construction and, provided the IdentityEvaluator and
// ContextBuilder it holds are safe for concurrent use, is safe for concurrent
// queries.
type LambdaEvaluator struct {
	identity                 IdentityEvaluator
	functionResourcePolicies map[string]*Policy
	contextBuilder           ContextBuilder
	constraints              DirectConstraintEvaluator
}

// NewLambdaEvaluator builds a LambdaEvaluator. functionResourcePolicies is keyed
// by function ARN; each value is the parsed resource policy (parse the raw,
// NON-url-encoded lambda:GetPolicy JSON via ParseResourcePolicy). contextBuilder
// is the policy-variable/condition context source (may be nil for a blank
// context). Mirrors LambdaResourcePolicyEvaluator.__init__.
func NewLambdaEvaluator(
	identity IdentityEvaluator,
	functionResourcePolicies map[string]*Policy,
	contextBuilder ContextBuilder,
	constraints ...DirectConstraintEvaluator,
) *LambdaEvaluator {
	if functionResourcePolicies == nil {
		functionResourcePolicies = map[string]*Policy{}
	}
	return &LambdaEvaluator{
		identity:                 identity,
		functionResourcePolicies: functionResourcePolicies,
		contextBuilder:           contextBuilder,
		constraints: func() DirectConstraintEvaluator {
			if len(constraints) > 0 {
				return constraints[0]
			}
			return nil
		}(),
	}
}

// EvaluateLambdaResourcePolicy checks whether principalArn can invoke the Lambda
// function, composing the resource policy with the identity side. Ported from
// LambdaResourcePolicyEvaluator.can_invoke_function (the action is
// lambda:InvokeFunction).
//
// A service principal ("…​.amazonaws.com") is authorized by the resource policy
// alone. Otherwise: an explicit deny on IAM or the resource policy wins;
// cross-account requires IAM AND the resource policy; same-account takes their
// union. When either account cannot be determined the check falls to the
// same-account rule, exactly as the Python does.
func (e *LambdaEvaluator) EvaluateLambdaResourcePolicy(principalArn, functionArn string) LambdaAccessCheckResult {
	const action = "lambda:InvokeFunction"

	functionAccount, functionOK := accountIDFromARN(functionArn)
	principalAccount, principalOK := accountIDFromARN(principalArn)

	// Service principals: resource policy only.
	if isServicePrincipalARN(principalArn) {
		rp := e.checkResourcePolicy(principalArn, action, functionArn)
		if rp.denied {
			return LambdaAccessCheckResult{Allowed: false, Denied: true, DenySource: "resource_policy"}
		}
		allowed := rp.allowed
		var allowSources []string
		if allowed {
			allowSources = []string{"resource_policy"}
		}
		return LambdaAccessCheckResult{
			Allowed:               allowed,
			ResourcePolicyAllowed: allowed,
			AllowSources:          allowSources,
			Conditions:            rp.conditions,
			HasConditions:         len(rp.conditions) > 0,
		}
	}

	isCrossAccount := principalOK && functionOK && principalAccount != functionAccount

	// Step 1: IAM policies.
	iamResult := e.checkIAMPolicies(principalArn, action, functionArn)
	if iamResult.denied {
		return LambdaAccessCheckResult{Allowed: false, Denied: true, DenySource: "iam"}
	}

	// Step 2: resource policy.
	rp := e.checkResourcePolicy(principalArn, action, functionArn)
	if rp.denied {
		return LambdaAccessCheckResult{Allowed: false, Denied: true, DenySource: "resource_policy"}
	}

	iamAllowed := iamResult.allowed
	rpAllowed := rp.allowed
	var directConstraint *PermissionCheckResult
	if !isCrossAccount {
		directConstraint = e.directConstraintsResult(principalArn, action, functionArn, rp.directRequiresBoundary)
		rpAllowed = rp.directAllowed && directConstraint.Allowed
	}

	// Step 3: authorization rules.
	var allowSources []string
	var conditions []map[string]any
	var allowed bool
	if isCrossAccount {
		// Cross-account: BOTH IAM AND resource policy must allow.
		if iamAllowed && rpAllowed {
			allowed = true
			allowSources = append(allowSources, "iam_policy", "resource_policy")
			conditions = append(conditions, iamResult.conditions...)
			conditions = append(conditions, rp.conditions...)
		} else {
			allowed = false
		}
	} else {
		// Same-account: IAM OR resource policy can allow.
		allowed = iamAllowed || rpAllowed
		if iamAllowed {
			allowSources = append(allowSources, "iam_policy")
			conditions = append(conditions, iamResult.conditions...)
		}
		if rpAllowed {
			allowSources = append(allowSources, "resource_policy")
			conditions = append(conditions, rp.directConditions...)
			conditions = append(conditions, directConstraint.Conditions...)
		}
	}

	return LambdaAccessCheckResult{
		Allowed:               allowed,
		IAMAllowed:            iamAllowed,
		ResourcePolicyAllowed: rpAllowed,
		AllowSources:          allowSources,
		Conditions:            conditions,
		HasConditions:         len(conditions) > 0,
	}
}

func (e *LambdaEvaluator) directConstraintsResult(principalArn, action, resourceArn string, requireBoundary bool) *PermissionCheckResult {
	if e.constraints == nil {
		return &PermissionCheckResult{Allowed: true, Outcome: OutcomeAllowed}
	}
	if requireBoundary {
		return e.constraints.CheckDirectGrantConstraints(principalArn, action, resourceArn, nil)
	}
	return e.constraints.CheckDirectGrantConstraintsDenyOnly(principalArn, action, resourceArn, nil)
}

// checkIAMPolicies delegates to the identity side. Ported from
// LambdaResourcePolicyEvaluator._check_iam_policies.
func (e *LambdaEvaluator) checkIAMPolicies(principalArn, action, resourceArn string) policyDecision {
	res := e.identity.CanPerformAction(principalArn, action, resourceArn)
	return policyDecision{allowed: res.Allowed, denied: res.Denied, conditions: res.Conditions}
}

// checkResourcePolicy evaluates the function resource policy for an allow/deny on
// (principal, action, function). Ported from
// LambdaResourcePolicyEvaluator._check_resource_policy.
//
// Unlike a bucket policy, a Lambda statement with no Resource imposes no resource
// constraint (it matches any target), and NotResource / NotPrincipal are not
// consulted — a statement must carry a Principal, matched against the target.
// Policy variables in Resource are substituted only under language version
// 2012-10-17.
func (e *LambdaEvaluator) checkResourcePolicy(principalArn, action, functionArn string) policyDecision {
	policyDoc := e.functionResourcePolicies[functionArn]
	if policyDoc == nil {
		return policyDecision{}
	}
	variablesEnabled := policyDoc.Version == "2012-10-17"

	getCtx := newContextMemo(e.contextBuilder, principalArn, action, functionArn)
	matchResource := func(pattern string) bool {
		if variablesEnabled && HasPolicyVariables(pattern) {
			resolved, ok := ResolvePolicyVariables(pattern, getCtx(), true)
			if !ok {
				return false
			}
			pattern = resolved
		}
		return resourceMatches(pattern, functionArn)
	}

	var matchedAllows, matchedDenies, directDenyOnlyAllows, directBoundaryAllows []MatchedStatement
	for idx := range policyDoc.Statements {
		st := &policyDoc.Statements[idx]
		effect := st.Effect
		if effect != "Allow" && effect != "Deny" {
			continue
		}
		if !StatementActionMatches(st, action) {
			continue
		}

		// A present, non-empty Resource must match; NotResource applies when the
		// target matches none of its exclusions. An absent selector is broad.
		if len(st.Resource) > 0 {
			resourceMatch := false
			for _, r := range st.Resource {
				if matchResource(r) {
					resourceMatch = true
					break
				}
			}
			if !resourceMatch {
				continue
			}
		} else if len(st.NotResource) > 0 {
			excluded := false
			for _, resource := range st.NotResource {
				if matchResource(resource) {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		grantKind := resourcePrincipalGrantKind(st, principalArn)
		if grantKind == principalGrantNone {
			continue
		}

		ms := MatchedStatement{Condition: st.Condition, Source: "lambda-resource-policy/" + strconv.Itoa(idx)}
		if effect == "Allow" {
			matchedAllows = append(matchedAllows, ms)
			if grantKind == principalGrantBroad || (grantKind == principalGrantExact && !strings.Contains(principalArn, ":role/")) {
				directDenyOnlyAllows = append(directDenyOnlyAllows, ms)
			} else if grantKind == principalGrantExact {
				directBoundaryAllows = append(directBoundaryAllows, ms)
			}
		} else {
			matchedDenies = append(matchedDenies, ms)
		}
	}

	if len(matchedAllows) == 0 && len(matchedDenies) == 0 {
		return policyDecision{}
	}
	resolution := ResolveMatchedStatements(matchedAllows, matchedDenies, getCtx)
	directDenyOnly := ResolveMatchedStatements(directDenyOnlyAllows, matchedDenies, getCtx)
	directBoundary := ResolveMatchedStatements(directBoundaryAllows, matchedDenies, getCtx)
	directAllowed := directDenyOnly.Allowed || directBoundary.Allowed
	directConditions := directBoundary.Conditions
	directRequiresBoundary := directBoundary.Allowed
	if directDenyOnly.Allowed {
		directConditions = directDenyOnly.Conditions
		directRequiresBoundary = false
	}
	return policyDecision{
		allowed:    resolution.Allowed,
		denied:     resolution.Denied,
		conditions: resolution.Conditions, directAllowed: directAllowed,
		directRequiresBoundary: directRequiresBoundary, directConditions: directConditions,
	}
}
