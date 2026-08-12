package model

// EC2 collected shapes (AWSHound's EC2Data / core/ingestion/ec2.py; see the package
// doc for the shared region-scoped/JSON conventions). The modeled subset:
// identity/network metadata for the node, the IAM instance profile (whose role is
// the escalation target), and the EBS block-device mappings from which per-instance
// volume ARNs are derived (see store/ec2.go).

// EC2Data is the top-level collected shape for AWS EC2: the account id plus every EC2
// instance discovered across the account's enabled regions.
type EC2Data struct {
	AccountId string        `json:"AccountId"`
	Instances []EC2Instance `json:"Instances"`
}

// EC2Instance is one EC2 instance from DescribeInstances, carrying the "Region" the
// collector injected. It mirrors the raw boto3 instance dict, narrowed to the fields
// the node parser and edge processors use. LaunchTime is the launch time rendered as
// a string (the Python parser's str(LaunchTime)); the collector formats it as RFC3339.
type EC2Instance struct {
	InstanceId          string                  `json:"InstanceId"`
	Region              string                  `json:"Region"`
	InstanceType        string                  `json:"InstanceType"`
	ImageId             string                  `json:"ImageId"`
	VpcId               string                  `json:"VpcId"`
	SubnetId            string                  `json:"SubnetId"`
	PrivateIpAddress    string                  `json:"PrivateIpAddress"`
	PublicIpAddress     string                  `json:"PublicIpAddress"`
	LaunchTime          string                  `json:"LaunchTime"`
	State               EC2State                `json:"State"`
	IamInstanceProfile  *EC2IamInstanceProfile  `json:"IamInstanceProfile,omitempty"`
	SecurityGroups      []EC2SecurityGroup      `json:"SecurityGroups"`
	Tags                []Tag                   `json:"Tags"`
	RootDeviceName      string                  `json:"RootDeviceName"`
	BlockDeviceMappings []EC2BlockDeviceMapping `json:"BlockDeviceMappings"`
}

// EC2State is an instance's lifecycle state; the node parser reads Name ("running",
// "stopped", ...). Mirrors boto3's State {"Code", "Name"} dict, narrowed to Name.
type EC2State struct {
	Name string `json:"Name"`
}

// EC2IamInstanceProfile is the instance profile associated with an instance. The node
// parser reads Arn (the profile ARN whose role the instance assumes); a nil pointer
// marks an instance with no profile, matching the Python's `if iam_profile` guard.
type EC2IamInstanceProfile struct {
	Arn string `json:"Arn"`
	Id  string `json:"Id,omitempty"`
}

// EC2SecurityGroup is one security group attached to an instance. The node parser
// json-encodes the slice verbatim into the "security_groups" property; field order
// (GroupName, GroupId) matches the boto3 GroupIdentifier shape.
type EC2SecurityGroup struct {
	GroupName string `json:"GroupName"`
	GroupId   string `json:"GroupId"`
}

// EC2BlockDeviceMapping is one block-device mapping on an instance. Its Ebs volume id
// (when present) is the source for the synthesized volume ARN
// arn:aws:ec2:<region>:<account>:volume/<id> used by the volume-based edges.
type EC2BlockDeviceMapping struct {
	DeviceName string        `json:"DeviceName"`
	Ebs        *EC2EbsDevice `json:"Ebs,omitempty"`
}

// EC2EbsDevice is the EBS half of a block-device mapping, carrying the VolumeId.
type EC2EbsDevice struct {
	VolumeId string `json:"VolumeId"`
}
