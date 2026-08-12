package model

// SSM collected shapes (AWSHound's SSMData / core/ingestion/ssm.py; see the package
// doc for the shared conventions). Only parameter METADATA is collected, never a
// parameter's value — a deliberate security choice, matching the Python collector.

// SSMData is the top-level collected shape for AWS SSM in one account: every
// Parameter Store parameter's metadata plus every SSM-managed instance discovered
// across the account's enabled regions.
type SSMData struct {
	AccountId        string               `json:"AccountId"`
	Parameters       []SSMParameter       `json:"Parameters"`
	ManagedInstances []SSMManagedInstance `json:"ManagedInstances"`
}

// SSMParameter is one Parameter Store parameter's metadata from DescribeParameters
// (never its value). ARN is the real parameter ARN; when a re-ingested blob lacks
// it, IngestSSM synthesizes arn:aws:ssm:{region}:{account}:parameter{name}. Region
// is stamped by the collector. Description/Tags are optional (omitempty) — the node
// parser emits them only when present. DescribeParameters does not return tags, so
// live collection leaves Tags nil; the field exists so an externally-collected blob
// round-trips and the node parser's tag handling stays faithful.
type SSMParameter struct {
	Name             string `json:"Name"`
	ARN              string `json:"ARN"`
	Type             string `json:"Type"`
	KeyId            string `json:"KeyId,omitempty"`
	Tier             string `json:"Tier"`
	Version          int64  `json:"Version"`
	LastModifiedDate string `json:"LastModifiedDate"`
	Description      string `json:"Description,omitempty"`
	DataType         string `json:"DataType"`
	Region           string `json:"Region"`
	Tags             []Tag  `json:"Tags,omitempty"`
}

// SSMManagedInstance is one SSM-managed instance from DescribeInstanceInformation.
// It is NOT emitted as a graph node; downstream SSM edge processors consume the
// managed-instance set to decide which EC2 instances SSM can send commands to or
// start a session on. The collector records only the fields AWSHound keeps:
// InstanceId, PlatformType, PingStatus, and the stamped Region.
type SSMManagedInstance struct {
	InstanceId   string `json:"InstanceId"`
	PlatformType string `json:"PlatformType"`
	PingStatus   string `json:"PingStatus"`
	Region       string `json:"Region"`
}
