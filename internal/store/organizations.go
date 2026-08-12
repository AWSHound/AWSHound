package store

import "github.com/AWSHound/AWSHound/internal/model"

// orgService is the resource-bag key for AWS Organizations data. It matches
// OrganizationsCollector.Service().
const orgService = "organizations"

// IngestOrganizations stores an AWS Organizations payload on the given account
// (the management or delegated-admin account it was collected from) and interns
// every org/SCP/RCP ARN into the shared ARN universe. It is the in-memory port of
// AWSHound's add_organization_data (core/models/_queries/organizations.py).
//
// Three resource kinds land in the account's generic bag, all under orgService:
//   - one *model.OrgRoot (the organization object + per-account OU paths), keyed by
//     the organization ARN — the source for the Organization and Account nodes;
//   - one *model.SCPPolicy per service-control policy, keyed by its ARN;
//   - one *model.RCPPolicy per resource-control policy, keyed by its ARN.
//
// SCPs and RCPs are stored as distinct named types so the typed accessors below
// can separate them with a type switch.
func IngestOrganizations(st *Store, accountID string, data *model.OrganizationsData) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)

	// Names are indexed store-wide, keyed by the account they name rather than the
	// account the org was collected from, so an account's own node parser can reach
	// the name too (see Account.ResolvedName).
	for id, name := range data.AccountNames {
		st.putOrgAccountName(id, name)
	}

	if orgArn := data.Organization.Arn; orgArn != "" {
		acct.PutResource(orgService, orgArn, &model.OrgRoot{
			Organization:    data.Organization,
			AccountOrgPaths: data.AccountOrgPaths,
			AccountNames:    data.AccountNames,
		})
		st.ARN().Intern(orgArn)
	}

	for i := range data.SCPPolicies {
		if data.SCPPolicies[i].Arn == "" {
			continue
		}
		p := model.SCPPolicy(data.SCPPolicies[i])
		acct.PutResource(orgService, p.Arn, &p)
		st.ARN().Intern(p.Arn)
	}

	for i := range data.RCPPolicies {
		if data.RCPPolicies[i].Arn == "" {
			continue
		}
		p := model.RCPPolicy(data.RCPPolicies[i])
		acct.PutResource(orgService, p.Arn, &p)
		st.ARN().Intern(p.Arn)
	}
}

// OrganizationRecord returns the account's organization aggregate (the
// Organization object plus per-account OU paths and names), or nil when no org
// data was ingested here.
func (a *Account) OrganizationRecord() *model.OrgRoot {
	for _, v := range a.Resources(orgService) {
		if root, ok := v.(*model.OrgRoot); ok {
			return root
		}
	}
	return nil
}

// SCPPolicyList returns the service-control policies ingested on this account,
// ordered by ARN (RCPs sharing the bag are filtered out by the type assertion).
func (a *Account) SCPPolicyList() []*model.SCPPolicy {
	return listResources[model.SCPPolicy](a, orgService)
}

// RCPPolicyList returns the resource-control policies ingested on this account,
// ordered by ARN (SCPs sharing the bag are filtered out by the type assertion).
func (a *Account) RCPPolicyList() []*model.RCPPolicy {
	return listResources[model.RCPPolicy](a, orgService)
}
