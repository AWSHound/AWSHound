package build

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// S3Nodes emits the account's S3 nodes: one AWS_S3Bucket per bucket and one
// AWS_S3Object per collected object. It is the combined port of the
// S3BucketNodeParser and S3ObjectNodeParser (core/graph/nodes/s3.py).
//
// Buckets are emitted in ascending ARN order and each bucket's objects in ascending
// key order, so a map-backed store still yields diff-stable output. Node ids and the
// "arn" property carry the raw ARN; the colon->underscore id encoding is applied
// later by the emit package.
func S3Nodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	buckets := a.S3BucketList()
	sort.Slice(buckets, func(i, j int) bool { return s3BucketArn(buckets[i]) < s3BucketArn(buckets[j]) })

	var nodes []*graph.Node

	// AWS_S3Bucket nodes.
	for _, b := range buckets {
		if b.Name == "" {
			continue
		}
		arn := s3BucketArn(b)
		n := graph.NewNode(arn, graph.KindS3Bucket)
		n.Set("name", accountID+":"+b.Name)
		n.Set("arn", arn)
		n.Set("region", s3RegionOr(b.Region))
		n.Set("account_id", accountID)
		n.Set("creation_date", b.CreationDate)
		if policy := s3PolicyJSON(b.BucketPolicy); policy != "" {
			n.Set("bucket_policy", policy)
		}
		if b.Acl != nil {
			n.Set("acl", jsonProp(b.Acl))
		}
		if b.PublicAccessBlock != nil {
			n.Set("public_access_block", jsonProp(b.PublicAccessBlock))
		}
		if b.OwnershipControls != "" {
			n.Set("ownership_controls", b.OwnershipControls)
		}
		if len(b.Tags) > 0 {
			n.Set("tags", jsonProp(b.Tags))
		}
		nodes = append(nodes, n)
	}

	// AWS_S3Object nodes (nested within their bucket).
	for _, b := range buckets {
		if b.Name == "" {
			continue
		}
		bucketArn := s3BucketArn(b)
		objects := append([]model.S3Object(nil), b.Objects...)
		sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
		for _, obj := range objects {
			if obj.Key == "" {
				continue
			}
			objectArn := "arn:aws:s3:::" + b.Name + "/" + obj.Key
			n := graph.NewNode(objectArn, graph.KindS3Object)
			n.Set("name", accountID+":"+b.Name+"/"+obj.Key)
			n.Set("arn", objectArn)
			n.Set("account_id", accountID)
			n.Set("bucket_arn", bucketArn)
			n.Set("bucket_name", b.Name)
			n.Set("size", obj.Size)
			n.Set("last_modified", obj.LastModified)
			n.Set("storage_class", s3StorageClassOr(obj.StorageClass))
			n.Set("etag", obj.ETag)
			nodes = append(nodes, n)
		}
	}

	return nodes
}

// s3BucketArn returns a bucket's ARN, falling back to the synthesized
// arn:aws:s3:::<name> when the stored ARN is empty — matching the node parser's
// bucket.get("Arn", f"arn:aws:s3:::{bucket_name}") default.
func s3BucketArn(b *model.S3Bucket) string {
	if b.Arn != "" {
		return b.Arn
	}
	return "arn:aws:s3:::" + b.Name
}

// s3RegionOr mirrors bucket.get("Region", "us-east-1").
func s3RegionOr(region string) string {
	if region == "" {
		return "us-east-1"
	}
	return region
}

// s3StorageClassOr mirrors obj.get("StorageClass", "STANDARD").
func s3StorageClassOr(storageClass string) string {
	if storageClass == "" {
		return "STANDARD"
	}
	return storageClass
}

// s3PolicyJSON normalizes a raw bucket-policy document to a compact JSON string for
// the "bucket_policy" property (mirroring json.dumps(json.loads(policy))). It
// returns "" for an absent, null, or empty policy so the caller omits the property,
// matching the Python's `if bucket_policy:` guard.
func s3PolicyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return ""
	}
	switch buf.String() {
	case "", "null", "{}", "[]":
		return ""
	}
	return buf.String()
}
