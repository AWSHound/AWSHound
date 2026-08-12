// Package model holds the raw AWS collector data shapes — the Go equivalents of
// AWSHound's core/models/types.py TypedDicts. Each <svc>.go file ports one
// service's <Svc>Data shape and the per-resource dicts its collector synthesizes
// (core/ingestion/<svc>.py).
//
// Conventions shared by every service shape are stated here once; each file's own
// comment notes only that service's quirks:
//
//   - JSON fidelity: field json tags match the keys the collector emits — the AWS
//     API / GAAD / SDK field names, or the casing AWSHound's collector synthesizes —
//     so collected JSON unmarshals directly and a captured graph re-ingests
//     identically.
//   - Region-scoped services (EC2, KMS, SSM, Lambda, CloudFormation, EKS): the
//     collector fans out over every enabled region and stamps each resource with an
//     injected "Region", merging them into one <Svc>Data for the session account.
//     Global services (IAM, S3, Organizations) collect in a single pass.
//   - Timestamps are stored as strings (Python's str(datetime); the Go collector
//     renders RFC3339 — see internal/collect).
//   - Only the subset of fields the node parsers and edge processors consume is
//     modeled; other API fields are intentionally dropped.
//
// This file covers the IAM / GetAccountAuthorizationDetails (GAAD) core, the
// most-used shape.
package model

// AuthDetails is the GetAccountAuthorizationDetails response (paginated pages
// merged). AWS returns policy documents as URL-encoded JSON strings.
type AuthDetails struct {
	UserDetailList  []UserDetail   `json:"UserDetailList"`
	GroupDetailList []GroupDetail  `json:"GroupDetailList"`
	RoleDetailList  []RoleDetail   `json:"RoleDetailList"`
	Policies        []PolicyDetail `json:"Policies"`
	// Federation providers are collected separately from GAAD but travel with it.
	SAMLProviders []SAMLProvider `json:"SAMLProviders,omitempty"`
	OIDCProviders []OIDCProvider `json:"OIDCProviders,omitempty"`
	// AccountAlias is the account's IAM alias (iam:ListAccountAliases), also
	// collected separately from GAAD. It is the only human-readable name available
	// for a standalone account, and it is optional — an account with no alias, or
	// one collected without iam:ListAccountAliases, leaves it empty.
	AccountAlias string `json:"AccountAlias,omitempty"`
}

// InlinePolicy is an embedded (inline) policy document on a principal. The
// document is a URL-encoded JSON string in the GAAD response.
type InlinePolicy struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument string `json:"PolicyDocument"`
}

// AttachedPolicy references a managed policy attached to a principal.
type AttachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// UserDetail is one entry of UserDetailList.
type UserDetail struct {
	Arn                 string           `json:"Arn"`
	Path                string           `json:"Path"`
	UserId              string           `json:"UserId"`
	UserName            string           `json:"UserName"`
	GroupList           []string         `json:"GroupList"`
	AttachedManagedPols []AttachedPolicy `json:"AttachedManagedPolicies"`
	UserPolicyList      []InlinePolicy   `json:"UserPolicyList"`
	PermissionsBoundary *PermBoundary    `json:"PermissionsBoundary,omitempty"`
	Tags                []Tag            `json:"Tags,omitempty"`
}

// GroupDetail is one entry of GroupDetailList.
type GroupDetail struct {
	Arn                 string           `json:"Arn"`
	Path                string           `json:"Path"`
	GroupId             string           `json:"GroupId"`
	GroupName           string           `json:"GroupName"`
	AttachedManagedPols []AttachedPolicy `json:"AttachedManagedPolicies"`
	GroupPolicyList     []InlinePolicy   `json:"GroupPolicyList"`
}

// RoleDetail is one entry of RoleDetailList.
type RoleDetail struct {
	Arn                      string            `json:"Arn"`
	Path                     string            `json:"Path"`
	RoleId                   string            `json:"RoleId"`
	RoleName                 string            `json:"RoleName"`
	AssumeRolePolicyDocument string            `json:"AssumeRolePolicyDocument"`
	AttachedManagedPols      []AttachedPolicy  `json:"AttachedManagedPolicies"`
	RolePolicyList           []InlinePolicy    `json:"RolePolicyList"`
	InstanceProfileList      []InstanceProfile `json:"InstanceProfileList"`
	PermissionsBoundary      *PermBoundary     `json:"PermissionsBoundary,omitempty"`
	Tags                     []Tag             `json:"Tags,omitempty"`
}

// PolicyDetail is one entry of Policies (a standalone managed policy with its
// versions). The default version's document holds the effective permissions.
type PolicyDetail struct {
	Arn              string          `json:"Arn"`
	Path             string          `json:"Path"`
	PolicyId         string          `json:"PolicyId"`
	PolicyName       string          `json:"PolicyName"`
	DefaultVersionId string          `json:"DefaultVersionId"`
	PolicyVersions   []PolicyVersion `json:"PolicyVersionList"`
	AttachmentCount  int             `json:"AttachmentCount"`
}

// PolicyVersion is one version of a managed policy.
type PolicyVersion struct {
	Document         string `json:"Document"`
	VersionId        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
}

// InstanceProfile is an EC2 instance profile wrapping a role.
type InstanceProfile struct {
	Arn                 string `json:"Arn"`
	InstanceProfileName string `json:"InstanceProfileName"`
	InstanceProfileId   string `json:"InstanceProfileId"`
}

// PermBoundary is a principal's permissions boundary.
type PermBoundary struct {
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
}

// SAMLProvider / OIDCProvider are federation identity providers.
type SAMLProvider struct {
	Arn string `json:"Arn"`
}

type OIDCProvider struct {
	Arn            string   `json:"Arn"`
	Url            string   `json:"Url"`
	ClientIDList   []string `json:"ClientIDList,omitempty"`
	ThumbprintList []string `json:"ThumbprintList,omitempty"`
}

// Tag is an AWS resource tag.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// KeepDefaultVersionOnly discards every non-default policy version, retaining
// only the one DefaultPolicyDocument would select. No reader consults a
// non-default version — the evaluator reaches the document through
// DefaultPolicyDocument and the node builder emits only the IsDefaultVersion
// entry — while the discarded documents dominate resident memory on a large org.
// Both predicates are retained, not just the first match: DefaultPolicyDocument
// selects on either, while the node builder selects on IsDefaultVersion alone, so
// dropping a version that satisfies only one of them could silently change output.
func (p *PolicyDetail) KeepDefaultVersionOnly() {
	kept := p.PolicyVersions[:0:0]
	for i := range p.PolicyVersions {
		if p.PolicyVersions[i].VersionId == p.DefaultVersionId || p.PolicyVersions[i].IsDefaultVersion {
			kept = append(kept, p.PolicyVersions[i])
		}
	}
	p.PolicyVersions = kept
}

// DefaultPolicyDocument returns the URL-encoded document string of a managed
// policy's default version, or "" if none.
func (p *PolicyDetail) DefaultPolicyDocument() string {
	for i := range p.PolicyVersions {
		if p.PolicyVersions[i].VersionId == p.DefaultVersionId || p.PolicyVersions[i].IsDefaultVersion {
			return p.PolicyVersions[i].Document
		}
	}
	return ""
}
