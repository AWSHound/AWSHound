package eval

import "strings"

// scopeDecision is the exact result for one AWS authorization-policy scope.
// Statements within a scope are alternatives; separate scopes are evaluated
// independently so their Conditions and NotResource carve-outs remain an AND.
type scopeDecision struct {
	allowed              bool
	denied               bool
	conditions           []map[string]any
	allow                []string
	deny                 []string
	blocking             string
	onlyComplementDenies bool
}

func grantActionMatches(g Grant, action string) bool {
	_, named := g.Actions[action]
	return named != g.Complement
}

func (pe *PolicyEvaluator) grantMatchesResource(g Grant, resource string, resourceIsPattern bool, ctx *RequestContext, variablesEnabled bool) bool {
	match := func(selector string) bool {
		if HasPolicyVariables(selector) && variablesEnabled {
			resolved, ok := ResolvePolicyVariables(selector, ctx, true)
			if !ok {
				return false
			}
			selector = resolved
		}
		if !resourceIsPattern {
			return resourceMatches(selector, resource)
		}
		_, ok := intersectPatterns(selector, resource)
		return ok
	}
	if g.Resource != nil {
		return match(*g.Resource)
	}
	if g.NotResource != nil {
		if !resourceIsPattern {
			return !match(*g.NotResource)
		}
		// A future-resource family is usable when at least one member lies
		// outside the exclusion. If the intersection is exactly the family,
		// every possible resource is excluded.
		intersection, ok := intersectPatterns(*g.NotResource, resource)
		return !ok || intersection != resource
	}
	return false
}

func versionForGrant(versions map[string]string, source string) bool {
	if i := strings.LastIndex(source, "/"); i >= 0 {
		source = source[:i]
	}
	return versions[source] == "2012-10-17"
}

func (pe *PolicyEvaluator) evaluateScope(policies []*CompiledPolicy, versions map[string]string, action, resource string, resourceIsPattern bool, contextFactory ContextFactory, requireAllow bool) scopeDecision {
	if len(policies) == 0 {
		if requireAllow {
			return scopeDecision{}
		}
		return scopeDecision{allowed: true}
	}
	ctx := contextFactory()
	var allows, denies []MatchedStatement
	onlyComplementDenies := true
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, grant := range policy.Grants {
			if !grantActionMatches(grant, action) || !pe.grantMatchesResource(grant, resource, resourceIsPattern, ctx, versionForGrant(versions, grant.Source)) {
				continue
			}
			matched := MatchedStatement{Condition: grant.Condition, Source: grant.Source}
			if grant.Effect == EffectAllow {
				allows = append(allows, matched)
			} else {
				denies = append(denies, matched)
				if !grant.Complement {
					onlyComplementDenies = false
				}
			}
		}
	}
	res := ResolveMatchedStatements(allows, denies, contextFactory)
	if res.Denied {
		blocking := ""
		if len(res.DenySources) > 0 {
			blocking = res.DenySources[0]
		}
		return scopeDecision{denied: true, deny: res.DenySources, blocking: blocking, onlyComplementDenies: onlyComplementDenies}
	}
	if requireAllow && !res.Allowed {
		return scopeDecision{}
	}
	return scopeDecision{allowed: true, conditions: res.Conditions, allow: res.AllowSources}
}

func policiesAllowAction(policies []*CompiledPolicy, action string) bool {
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, grant := range policy.Grants {
			if grant.Effect == EffectAllow && grantActionMatches(grant, action) {
				return true
			}
		}
	}
	return false
}

func (pe *PolicyEvaluator) compileDocuments(docs []policyDoc) ([]*CompiledPolicy, map[string]string) {
	policies := make([]*CompiledPolicy, 0, len(docs))
	versions := make(map[string]string, len(docs))
	for _, doc := range docs {
		compiled := pe.compileDoc(doc.source, doc.doc)
		policies = append(policies, compiled.cp)
		versions[doc.source] = compiled.version
	}
	return policies, versions
}

func (pe *PolicyEvaluator) orgScopeDecision(accountID string, rcp bool, action, resource string, resourceIsPattern bool, contextFactory ContextFactory) scopeDecision {
	levels := pe.orgLevels(accountID, rcp)
	allConditions := []map[string]any{}
	for _, level := range levels.levels {
		decision := pe.evaluateScope(level, levels.versions, action, resource, resourceIsPattern, contextFactory, true)
		if !decision.allowed {
			if decision.blocking == "" {
				for _, policy := range level {
					for _, grant := range policy.Grants {
						if decision.blocking == "" || grant.Source < decision.blocking {
							decision.blocking = grant.Source
						}
					}
				}
			}
			return decision
		}
		allConditions = append(allConditions, decision.conditions...)
	}
	return scopeDecision{allowed: true, conditions: allConditions}
}

func (pe *PolicyEvaluator) resourceAccount(resourceArn string) string {
	if resource := pe.resourceMetadata(resourceArn); resource != nil && resource.accountID != "" {
		return resource.accountID
	}
	accountID, _ := accountIDFromARN(resourceArn)
	return accountID
}

func isServiceLinkedRole(principalArn string) bool {
	return strings.Contains(principalArn, ":role/aws-service-role/")
}

func immutableServiceLinkedRoleAction(principalArn, action string) bool {
	if !isServiceLinkedRole(principalArn) {
		return false
	}
	switch strings.ToLower(action) {
	case "iam:attachrolepolicy", "iam:deleterole", "iam:deleterolepermissionsboundary",
		"iam:deleterolepolicy", "iam:detachrolepolicy", "iam:putrolepermissionsboundary",
		"iam:putrolepolicy", "iam:updateassumerolepolicy":
		return true
	default:
		return false
	}
}
