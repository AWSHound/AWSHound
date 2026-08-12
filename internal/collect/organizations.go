package collect

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// OrganizationsCollector fetches AWS Organizations data (SCPs, RCPs, OU hierarchy; a
// global collector — see the package doc). The whole payload is collected from the
// single session account (the management or delegated-admin account whose credentials
// can call Organizations).
type OrganizationsCollector struct{}

// Service returns the collector's service identifier.
func (OrganizationsCollector) Service() string { return "organizations" }

// Fetch collects the organization description, the SCP and RCP policies with their
// targets, and the OU hierarchy — resolving which accounts each policy applies to
// and each member account's OU path. It mirrors OrganizationsCollector.fetch.
func (OrganizationsCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	if err := s.limiter.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.limiter.release()
	defer s.tick()

	// Organizations has a single global endpoint; regionCfg supplies the default
	// region when the session has none resolved.
	client := organizations.NewFromConfig(s.regionCfg(""))

	// 1. Describe the organization.
	orgOut, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return nil, err
	}
	organization := toOrganization(orgOut.Organization)

	// 2. Build the OU hierarchy (root -> OUs -> accounts), the per-account OU path
	// used for aws:PrincipalOrgPaths / aws:ResourceOrgPaths condition keys, and each
	// account's org-registered name.
	hierarchy, accountPaths, accountNames, err := buildOrgHierarchy(ctx, s, client, organization.Id)
	if err != nil {
		return nil, err
	}

	// 3. Collect SCP policies.
	scpPolicies, err := collectOrgPolicies(ctx, s, client, orgtypes.PolicyTypeServiceControlPolicy, hierarchy)
	if err != nil {
		return nil, err
	}

	// 4. Collect RCP policies.
	rcpPolicies, err := collectOrgPolicies(ctx, s, client, orgtypes.PolicyTypeResourceControlPolicy, hierarchy)
	if err != nil {
		return nil, err
	}

	return &model.OrganizationsData{
		Organization:    organization,
		SCPPolicies:     scpPolicies,
		RCPPolicies:     rcpPolicies,
		AccountOrgPaths: accountPaths,
		AccountNames:    accountNames,
	}, nil
}

// toOrganization maps the SDK organization object to the collected model shape.
func toOrganization(o *orgtypes.Organization) model.Organization {
	if o == nil {
		return model.Organization{}
	}
	return model.Organization{
		Id:                 aws.ToString(o.Id),
		Arn:                aws.ToString(o.Arn),
		FeatureSet:         string(o.FeatureSet),
		MasterAccountId:    aws.ToString(o.MasterAccountId),
		MasterAccountArn:   aws.ToString(o.MasterAccountArn),
		MasterAccountEmail: aws.ToString(o.MasterAccountEmail),
	}
}

// buildOrgHierarchy walks the org tree from its roots and returns, per OU/root ID,
// the set of descendant account IDs, each account's OU path string in
// aws:PrincipalOrgPaths format ("o-org/r-root/ou-.../" with a trailing slash), and
// each account's org-registered name. It is the port of
// OrganizationsCollector._build_hierarchy, extended with the name map: the
// ListAccountsForParent pages the walk already consumes carry Name alongside Id, so
// the name is free here and would otherwise need a per-account DescribeAccount.
func buildOrgHierarchy(ctx context.Context, s *Session, client *organizations.Client, orgID string) (map[string]map[string]struct{}, map[string]string, map[string]string, error) {
	ouChildren := map[string][]string{}     // parent ID -> child OU IDs
	directAccounts := map[string][]string{} // parent ID -> direct child account IDs
	parentOf := map[string]string{}         // child (OU or account) -> parent ID
	accountNames := map[string]string{}     // account ID -> org-registered name

	// Roots.
	var rootIDs []string
	rootsPager := organizations.NewListRootsPaginator(client, &organizations.ListRootsInput{})
	for rootsPager.HasMorePages() {
		page, err := rootsPager.NextPage(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, r := range page.Roots {
			rootIDs = append(rootIDs, aws.ToString(r.Id))
		}
	}

	// BFS to discover all OUs and accounts.
	queue := append([]string{}, rootIDs...)
	for len(queue) > 0 {
		parentID := queue[0]
		queue = queue[1:]

		// Child OUs.
		ouPager := organizations.NewListOrganizationalUnitsForParentPaginator(client,
			&organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parentID)})
		for ouPager.HasMorePages() {
			page, err := ouPager.NextPage(ctx)
			if err != nil {
				return nil, nil, nil, err
			}
			for _, ou := range page.OrganizationalUnits {
				ouID := aws.ToString(ou.Id)
				ouChildren[parentID] = append(ouChildren[parentID], ouID)
				parentOf[ouID] = parentID
				queue = append(queue, ouID)
			}
		}

		// Direct accounts.
		acctPager := organizations.NewListAccountsForParentPaginator(client,
			&organizations.ListAccountsForParentInput{ParentId: aws.String(parentID)})
		for acctPager.HasMorePages() {
			page, err := acctPager.NextPage(ctx)
			if err != nil {
				return nil, nil, nil, err
			}
			for _, acct := range page.Accounts {
				acctID := aws.ToString(acct.Id)
				directAccounts[parentID] = append(directAccounts[parentID], acctID)
				parentOf[acctID] = parentID
				// An unnamed account stays out of the map entirely: the graph omits
				// the name property rather than carrying an empty one.
				if name := aws.ToString(acct.Name); name != "" {
					accountNames[acctID] = name
				}
			}
		}

		// One progress unit per fully-walked tree node, so the org straggler (this
		// sequential BFS on the management account) advances node-by-node. Both
		// pagers above succeeded to reach here, so the added unit is always ticked.
		// See Session.addWork.
		s.addWork(1)
		s.tick()
	}

	// Resolve each parent to the set of all descendant accounts (memoized).
	children := map[string]map[string]struct{}{}
	var resolve func(string) map[string]struct{}
	resolve = func(parentID string) map[string]struct{} {
		if r, ok := children[parentID]; ok {
			return r
		}
		result := map[string]struct{}{}
		for _, a := range directAccounts[parentID] {
			result[a] = struct{}{}
		}
		for _, childOU := range ouChildren[parentID] {
			for a := range resolve(childOU) {
				result[a] = struct{}{}
			}
		}
		children[parentID] = result
		return result
	}
	for _, rootID := range rootIDs {
		resolve(rootID)
	}
	for parentID := range ouChildren {
		resolve(parentID)
	}

	accountPaths := buildAccountPaths(orgID, parentOf, directAccounts)
	return children, accountPaths, accountNames, nil
}

// buildAccountPaths builds each account's OU path string by walking from the
// account up its parent chain to the root, then reversing to root-down order.
// Port of organizations.py's _build_account_paths.
func buildAccountPaths(orgID string, parentOf map[string]string, directAccounts map[string][]string) map[string]string {
	accountIDs := map[string]struct{}{}
	for _, accts := range directAccounts {
		for _, a := range accts {
			accountIDs[a] = struct{}{}
		}
	}

	paths := map[string]string{}
	for accountID := range accountIDs {
		var chain []string
		cursor, ok := parentOf[accountID]
		for ok {
			chain = append(chain, cursor)
			cursor, ok = parentOf[cursor]
		}
		// chain is leaf-to-root; reverse for root-down order.
		for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
			chain[i], chain[j] = chain[j], chain[i]
		}
		components := append([]string{orgID}, chain...)
		paths[accountID] = strings.Join(components, "/") + "/"
	}
	return paths
}

// collectOrgPolicies lists policies of the given type, fetches each policy's
// document and attach targets, and resolves the targets to a flattened set of
// member account IDs via the OU hierarchy. It is the port of
// OrganizationsCollector._collect_policies. When Organizations is not in use the
// list call fails with AWSOrganizationsNotInUseException, which is swallowed to an
// empty result — matching the Python.
func collectOrgPolicies(ctx context.Context, s *Session, client *organizations.Client, filter orgtypes.PolicyType, hierarchy map[string]map[string]struct{}) ([]model.OrgPolicy, error) {
	var summaries []orgtypes.PolicySummary
	listPager := organizations.NewListPoliciesPaginator(client, &organizations.ListPoliciesInput{Filter: filter})
	for listPager.HasMorePages() {
		page, err := listPager.NextPage(ctx)
		if err != nil {
			var notInUse *orgtypes.AWSOrganizationsNotInUseException
			if errors.As(err, &notInUse) {
				return nil, nil
			}
			return nil, err
		}
		summaries = append(summaries, page.Policies...)
	}

	var policies []model.OrgPolicy
	for _, summary := range summaries {
		policyID := aws.ToString(summary.Id)

		// Full policy document.
		detail, err := client.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: aws.String(policyID)})
		if err != nil {
			return nil, err
		}
		content := "{}"
		arn := aws.ToString(summary.Arn)
		name := aws.ToString(summary.Name)
		var awsManaged bool
		if detail.Policy != nil {
			if detail.Policy.Content != nil {
				content = aws.ToString(detail.Policy.Content)
			}
			if ps := detail.Policy.PolicySummary; ps != nil {
				if ps.Arn != nil {
					arn = aws.ToString(ps.Arn)
				}
				if ps.Name != nil {
					name = aws.ToString(ps.Name)
				}
				awsManaged = ps.AwsManaged
			}
		}

		// Attach targets.
		var targets []model.OrgPolicyTarget
		targetPager := organizations.NewListTargetsForPolicyPaginator(client,
			&organizations.ListTargetsForPolicyInput{PolicyId: aws.String(policyID)})
		for targetPager.HasMorePages() {
			page, err := targetPager.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, t := range page.Targets {
				targets = append(targets, model.OrgPolicyTarget{
					TargetId: aws.ToString(t.TargetId),
					Type:     string(t.Type),
				})
			}
		}

		// Resolve target account IDs through the hierarchy.
		accountSet := map[string]struct{}{}
		for _, t := range targets {
			switch t.Type {
			case string(orgtypes.TargetTypeAccount):
				accountSet[t.TargetId] = struct{}{}
			case string(orgtypes.TargetTypeRoot), string(orgtypes.TargetTypeOrganizationalUnit):
				for a := range hierarchy[t.TargetId] {
					accountSet[a] = struct{}{}
				}
			}
		}
		accountIDs := make([]string, 0, len(accountSet))
		for a := range accountSet {
			accountIDs = append(accountIDs, a)
		}
		sort.Strings(accountIDs)

		policies = append(policies, model.OrgPolicy{
			Id:         policyID,
			Arn:        arn,
			Name:       name,
			Content:    content,
			AwsManaged: awsManaged,
			AccountIds: accountIDs,
			Targets:    targets,
		})

		// One progress unit per fully-processed policy (its DescribePolicy +
		// ListTargetsForPolicy walk). Placed after the fallible calls so an
		// error-out above never leaves an added unit un-ticked. See Session.addWork.
		s.addWork(1)
		s.tick()
	}

	return policies, nil
}
