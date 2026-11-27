package model

// S3 collected shapes (AWSHound's S3Data / core/ingestion/s3.py; see the package doc
// for the shared conventions). ListBuckets is a GLOBAL call, so one S3Data describes
// every bucket in the account; each bucket carries its region (resolved per bucket
// via GetBucketLocation), policy, ACL, public-access-block, ownership controls, tags,
// and a bounded slice of objects.

import "encoding/json"

// S3Data is the top-level collected shape for S3 in one account.
//
//   - Buckets: every bucket ListBuckets returned, each enriched with its
//     per-bucket control-plane data.
//   - AccountPublicAccessBlock: the account-level Block Public Access config
//     (s3control:GetPublicAccessBlock), or nil when unset or unreadable.
type S3Data struct {
	AccountId                string                          `json:"AccountId"`
	Buckets                  []S3Bucket                      `json:"Buckets"`
	AccountPublicAccessBlock *PublicAccessBlockConfiguration `json:"AccountPublicAccessBlock,omitempty"`
}

// S3Bucket is one bucket with its collected control-plane metadata. BucketPolicy
// is the raw policy JSON document (opaque, held as RawMessage so it round-trips
// unchanged); Acl / PublicAccessBlock are nil when the corresponding call was
// denied or unset; OwnershipControls is the first rule's ObjectOwnership value
// ("" when absent).
type S3Bucket struct {
	Name              string                          `json:"Name"`
	Arn               string                          `json:"Arn"`
	CreationDate      string                          `json:"CreationDate"`
	Region            string                          `json:"Region"`
	BucketPolicy      json.RawMessage                 `json:"BucketPolicy,omitempty"`
	Acl               *BucketACL                      `json:"Acl,omitempty"`
	PublicAccessBlock *PublicAccessBlockConfiguration `json:"PublicAccessBlock,omitempty"`
	OwnershipControls string                          `json:"OwnershipControls,omitempty"`
	Tags              []Tag                           `json:"Tags,omitempty"`
	Objects           []S3Object                      `json:"Objects,omitempty"`
}

// S3Object is one object listed from a bucket (bounded by the collector's
// per-bucket cap). Size is bytes; LastModified is a timestamp string;
// StorageClass defaults to "STANDARD".
type S3Object struct {
	Key          string `json:"Key"`
	Size         int64  `json:"Size"`
	LastModified string `json:"LastModified"`
	StorageClass string `json:"StorageClass"`
	ETag         string `json:"ETag"`
}

// BucketACL is the meaningful subset of GetBucketAcl (owner + grants), keyed to
// match boto3's response casing so the node parser's json-encoded "acl" property
// stays semantically identical to AWSHound's. (AWSHound stored boto3's whole
// response dict, including non-deterministic ResponseMetadata; that noise is
// intentionally dropped here.)
type BucketACL struct {
	Owner  *ACLOwner  `json:"Owner,omitempty"`
	Grants []ACLGrant `json:"Grants,omitempty"`
}

// ACLOwner is the bucket owner's canonical identity.
type ACLOwner struct {
	DisplayName string `json:"DisplayName,omitempty"`
	ID          string `json:"ID,omitempty"`
}

// ACLGrant pairs a grantee with the permission granted.
type ACLGrant struct {
	Grantee    *ACLGrantee `json:"Grantee,omitempty"`
	Permission string      `json:"Permission,omitempty"`
}

// ACLGrantee identifies who a grant is for. Type is the grantee kind
// ("CanonicalUser", "Group", "AmazonCustomerByEmail"); Group grantees carry a URI
// (e.g. the AllUsers / AuthenticatedUsers group).
type ACLGrantee struct {
	Type         string `json:"Type,omitempty"`
	DisplayName  string `json:"DisplayName,omitempty"`
	EmailAddress string `json:"EmailAddress,omitempty"`
	ID           string `json:"ID,omitempty"`
	URI          string `json:"URI,omitempty"`
}

// PublicAccessBlockConfiguration is the Block Public Access setting, used both
// per-bucket (S3:GetPublicAccessBlock) and account-wide
// (s3control:GetPublicAccessBlock). All four flags are always present in an AWS
// response, so they are plain bools (no omitempty) to mirror boto3's dict. Field
// order matches the AWS-documented response order for stable json output.
type PublicAccessBlockConfiguration struct {
	BlockPublicAcls       bool `json:"BlockPublicAcls"`
	IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
	BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
	RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
}
