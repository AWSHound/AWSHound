package model

// CloudFormation collected shapes (AWSHound's CloudFormationData /
// core/ingestion/cloudformation.py; see the package doc for the shared conventions).
// The modeled subset: the stack's identity/status/role for the
// AWS_CloudFormationStack node, the StackSet's permission model and admin/exec roles
// for the AWS_CloudFormationStackSet node (the UpdateStackSet / PassRole edge
// targets), and each stack's resource summaries (from which the stack ->
// PhysicalResourceId map the pass-role edges use is derived).

// CloudFormationData is the top-level collected shape for AWS CloudFormation: the
// account id, the session's default region, and every stack + StackSet discovered
// across the account's enabled regions. Region mirrors the Python collector's
// default_region (session.region_name or "us-east-1"); the per-stack / per-StackSet
// Region carries the region each was actually found in.
type CloudFormationData struct {
	AccountId string                   `json:"AccountId"`
	Region    string                   `json:"Region"`
	Stacks    []CloudFormationStack    `json:"Stacks"`
	StackSets []CloudFormationStackSet `json:"StackSets"`
}

// CloudFormationStack is one stack from DescribeStacks, carrying the "Region" the
// collector injected and enriched with its ListStackResources summaries. StackId is
// the stack ARN — the node id and the resource-bag key. RoleARN is the service role
// CloudFormation assumes to act on the stack (the pass-role escalation target);
// empty when the stack has no explicit role.
type CloudFormationStack struct {
	StackName    string                        `json:"StackName"`
	StackId      string                        `json:"StackId"`
	RoleARN      string                        `json:"RoleARN"`
	Capabilities []string                      `json:"Capabilities"`
	StackStatus  string                        `json:"StackStatus"`
	Region       string                        `json:"Region"`
	Tags         []Tag                         `json:"Tags"`
	Resources    []CloudFormationStackResource `json:"Resources"`
}

// CloudFormationStackResource is one resource managed by a stack, from
// ListStackResources. PhysicalResourceId keys the resource in AWSHound's store and
// feeds the stack -> physical-id map the pass-role-via-CloudFormation edges consume.
type CloudFormationStackResource struct {
	LogicalResourceId  string `json:"LogicalResourceId"`
	PhysicalResourceId string `json:"PhysicalResourceId"`
	ResourceType       string `json:"ResourceType"`
	ResourceStatus     string `json:"ResourceStatus"`
}

// CloudFormationStackSet is one StackSet from DescribeStackSet, carrying the "Region"
// it was listed in. StackSetARN is the node id and resource-bag key. PermissionModel
// is SERVICE_MANAGED or SELF_MANAGED; AdministrationRoleARN / ExecutionRoleName apply
// only to SELF_MANAGED sets and are the targets of the
// AWS_CanPassRoleViaCloudFormationStackSet(Update) edges.
type CloudFormationStackSet struct {
	StackSetName          string `json:"StackSetName"`
	StackSetId            string `json:"StackSetId"`
	StackSetARN           string `json:"StackSetARN"`
	PermissionModel       string `json:"PermissionModel"`
	Status                string `json:"Status"`
	AdministrationRoleARN string `json:"AdministrationRoleARN"`
	ExecutionRoleName     string `json:"ExecutionRoleName"`
	Region                string `json:"Region"`
}
