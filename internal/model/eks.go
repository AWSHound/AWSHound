package model

// EKS collected shapes (AWSHound's EKSData / core/ingestion/eks.py; see the package
// doc for the shared conventions). Quirk: unlike the sibling services, the json tags
// are camelCase (nodegroupArn, scalingConfig, instanceTypes, ...), matching the
// boto3/AWS response field names the collector stores. Four resource kinds travel
// together: clusters and node groups become graph nodes (see build/eks.go); access
// entries and Pod Identity associations are stored for the EKS edge processors.

// EKSData is the top-level collected shape for AWS EKS: the account id plus the
// clusters, managed node groups, access entries, and Pod Identity associations
// discovered across the account's enabled regions. It mirrors the Python EKSData keys.
type EKSData struct {
	AccountId               string                      `json:"AccountId"`
	Clusters                []EKSCluster                `json:"Clusters"`
	NodeGroups              []EKSNodeGroup              `json:"NodeGroups"`
	AccessEntries           []EKSAccessEntry            `json:"AccessEntries"`
	PodIdentityAssociations []EKSPodIdentityAssociation `json:"PodIdentityAssociations"`
}

// EKSCluster is one cluster from DescribeCluster, carrying the "Region" the collector
// injected. Narrowed to the fields the node parser reads: identity/network metadata,
// the control-plane RoleArn, and the OIDC issuer (nested under identity.oidc) that the
// IRSA edge keys off. CreatedAt is the creation time rendered as an RFC3339 string.
type EKSCluster struct {
	Arn             string            `json:"arn"`
	Name            string            `json:"name"`
	Region          string            `json:"Region"`
	Status          string            `json:"status"`
	Version         string            `json:"version"`
	RoleArn         string            `json:"roleArn"`
	Endpoint        string            `json:"endpoint"`
	PlatformVersion string            `json:"platformVersion"`
	Identity        EKSIdentity       `json:"identity"`
	Tags            map[string]string `json:"tags,omitempty"`
	CreatedAt       string            `json:"createdAt,omitempty"`
}

// EKSIdentity is the identity-provider block of a cluster; the node parser reads
// Oidc.Issuer (or "" when absent), matching the Python's
// identity.get("oidc", {}).get("issuer", "").
type EKSIdentity struct {
	Oidc EKSOIDC `json:"oidc"`
}

// EKSOIDC carries the cluster's OIDC issuer URL — the trust anchor for IRSA roles.
type EKSOIDC struct {
	Issuer string `json:"issuer"`
}

// EKSNodeGroup is one managed node group from DescribeNodegroup, carrying the injected
// "Region". NodeRole is the IAM role its EC2 instances assume (the escalation target
// for node-group edges), while Resources identifies its managed infrastructure for
// EC2 condition evaluation. CreatedAt/ModifiedAt are RFC3339 strings.
type EKSNodeGroup struct {
	NodegroupArn  string                 `json:"nodegroupArn"`
	NodegroupName string                 `json:"nodegroupName"`
	Region        string                 `json:"Region"`
	ClusterName   string                 `json:"clusterName"`
	NodeRole      string                 `json:"nodeRole"`
	Status        string                 `json:"status"`
	AmiType       string                 `json:"amiType"`
	CapacityType  string                 `json:"capacityType"`
	InstanceTypes []string               `json:"instanceTypes"`
	ScalingConfig EKSScalingConfig       `json:"scalingConfig"`
	Resources     *EKSNodeGroupResources `json:"resources,omitempty"`
	Tags          map[string]string      `json:"tags,omitempty"`
	CreatedAt     string                 `json:"createdAt,omitempty"`
	ModifiedAt    string                 `json:"modifiedAt,omitempty"`
}

// EKSNodeGroupResources identifies infrastructure owned by a managed node group.
// Auto Scaling group names can be joined to EC2's aws:autoscaling:groupName tag.
type EKSNodeGroupResources struct {
	AutoScalingGroups         []EKSAutoScalingGroup `json:"autoScalingGroups"`
	RemoteAccessSecurityGroup string                `json:"remoteAccessSecurityGroup,omitempty"`
}

// EKSAutoScalingGroup names an Auto Scaling group managed by EKS.
type EKSAutoScalingGroup struct {
	Name string `json:"name"`
}

// EKSScalingConfig is a node group's Auto Scaling sizing. The node parser emits each
// field as an int property, defaulting to 0 when the block is absent — which a
// zero-value EKSScalingConfig gives for free, matching the Python's
// scalingConfig.get("minSize", 0).
type EKSScalingConfig struct {
	MinSize     int `json:"minSize"`
	MaxSize     int `json:"maxSize"`
	DesiredSize int `json:"desiredSize"`
}

// EKSAccessEntry is an enriched DescribeAccessEntry result: the IAM PrincipalArn mapped
// into the cluster's Kubernetes RBAC, plus the associated access policies fetched via
// ListAssociatedAccessPolicies (the Python collector's accessPolicies enrichment).
// Consumed by the EKS access-entry edge processors, not by a node parser.
type EKSAccessEntry struct {
	ClusterName      string                      `json:"clusterName"`
	PrincipalArn     string                      `json:"principalArn"`
	AccessEntryArn   string                      `json:"accessEntryArn,omitempty"`
	Type             string                      `json:"type,omitempty"`
	Username         string                      `json:"username,omitempty"`
	KubernetesGroups []string                    `json:"kubernetesGroups,omitempty"`
	AccessPolicies   []EKSAssociatedAccessPolicy `json:"accessPolicies"`
	CreatedAt        string                      `json:"createdAt,omitempty"`
	ModifiedAt       string                      `json:"modifiedAt,omitempty"`
	Tags             map[string]string           `json:"tags,omitempty"`
}

// EKSAssociatedAccessPolicy is one access policy bound to an access entry (from
// ListAssociatedAccessPolicies): the policy ARN and the scope it applies at.
type EKSAssociatedAccessPolicy struct {
	PolicyArn    string         `json:"policyArn"`
	AccessScope  EKSAccessScope `json:"accessScope"`
	AssociatedAt string         `json:"associatedAt,omitempty"`
	ModifiedAt   string         `json:"modifiedAt,omitempty"`
}

// EKSAccessScope is the scope of an associated access policy: "cluster" or "namespace"
// (Type), with the namespace list when namespace-scoped.
type EKSAccessScope struct {
	Type       string   `json:"type"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// EKSPodIdentityAssociation is a DescribePodIdentityAssociation result: a Kubernetes
// service account (Namespace/ServiceAccount) in a cluster mapped to an IAM RoleArn.
// The Pod Identity edge processor uses the (cluster, role) mapping; stored here for it.
type EKSPodIdentityAssociation struct {
	ClusterName    string            `json:"clusterName"`
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"serviceAccount"`
	RoleArn        string            `json:"roleArn"`
	AssociationArn string            `json:"associationArn,omitempty"`
	AssociationId  string            `json:"associationId,omitempty"`
	CreatedAt      string            `json:"createdAt,omitempty"`
	ModifiedAt     string            `json:"modifiedAt,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
}
