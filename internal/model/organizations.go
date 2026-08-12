package model

// Organizations collected shapes (AWSHound's OrganizationsData /
// core/ingestion/organizations.py; see the package doc for the shared conventions).
// Organizations is a global service: one payload describes the whole org — the
// organization object, its SCP/RCP policies with resolved targets, and each member
// account's OU path.

// OrganizationsData is the top-level collected shape for AWS Organizations.
//
//   - Organization: the DescribeOrganization result (subset used by the graph).
//   - SCPPolicies / RCPPolicies: service- and resource-control policies, each with
//     its policy document and the flattened set of member accounts it applies to.
//   - AccountOrgPaths: each member account ID mapped to its OU path string in AWS
//     aws:PrincipalOrgPaths format ("o-org/r-root/ou-.../" with a trailing slash).
//   - AccountNames: each member account ID mapped to its org-registered account
//     name. It comes free with the ListAccountsForParent pages the OU walk already
//     paginates, so it costs no extra call and no extra permission. An account with
//     no name reported is absent from the map rather than mapped to "".
type OrganizationsData struct {
	Organization    Organization      `json:"Organization"`
	SCPPolicies     []OrgPolicy       `json:"SCPPolicies"`
	RCPPolicies     []OrgPolicy       `json:"RCPPolicies"`
	AccountOrgPaths map[string]string `json:"AccountOrgPaths"`
	AccountNames    map[string]string `json:"AccountNames,omitempty"`
}

// Organization mirrors the DescribeOrganization "Organization" object (the subset
// the graph consumes). Every account in the org resolves to the same
// MasterAccountId, so an account whose ID equals MasterAccountId is the
// management account.
type Organization struct {
	Id                 string `json:"Id"`
	Arn                string `json:"Arn"`
	FeatureSet         string `json:"FeatureSet"`
	MasterAccountId    string `json:"MasterAccountId"`
	MasterAccountArn   string `json:"MasterAccountArn,omitempty"`
	MasterAccountEmail string `json:"MasterAccountEmail,omitempty"`
}

// OrgPolicy is one SCP or RCP with its resolved target accounts. It mirrors the
// policy dicts in OrganizationsData.SCPPolicies / RCPPolicies.
//
// AccountIds is the flattened resolution of Targets: an ACCOUNT target contributes
// itself, while ROOT / ORGANIZATIONAL_UNIT targets contribute every descendant
// account. Targets preserves the raw attach level so the per-level SCP/RCP
// hierarchy (and FullAWSAccess detachment) can be reconstructed downstream.
type OrgPolicy struct {
	Id         string            `json:"Id"`
	Arn        string            `json:"Arn"`
	Name       string            `json:"Name"`
	Content    string            `json:"Content"`
	AwsManaged bool              `json:"AwsManaged"`
	AccountIds []string          `json:"AccountIds"`
	Targets    []OrgPolicyTarget `json:"Targets"`
}

// OrgPolicyTarget is a raw policy attach target (root, OU, or account). Type is
// one of "ROOT", "ORGANIZATIONAL_UNIT", or "ACCOUNT".
type OrgPolicyTarget struct {
	TargetId string `json:"TargetId"`
	Type     string `json:"Type"`
}

// SCPPolicy and RCPPolicy are distinct named views over OrgPolicy so the store's
// generic resource bag can hold both and typed accessors can tell them apart via a
// type switch — they carry identical fields but map to distinct node kinds
// (AWS_ServiceControlPolicy vs AWS_ResourceControlPolicy).
type SCPPolicy OrgPolicy

// RCPPolicy — see SCPPolicy.
type RCPPolicy OrgPolicy

// OrgRoot is the store-side aggregate kept under the organization's ARN: the
// Organization object bundled with the per-account OU path and name maps. Keeping
// them together lets Account nodes be decorated with org_id / org_path /
// management_account_id / name from a single lookup. It is built in memory during
// ingestion and is not part of the collected JSON shape.
type OrgRoot struct {
	Organization    Organization
	AccountOrgPaths map[string]string
	AccountNames    map[string]string
}
