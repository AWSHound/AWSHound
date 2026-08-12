package store

import "strings"

// ResourceType derives an ARN's resource type from its structure alone, with no
// external (SAR) data — the type tag the evaluation universe carries so an edge's
// candidate resources can be filtered to the type its action acts on (§7 of
// docs/authorization-tensor.md).
//
// An ARN is arn:partition:service:region:account:resource, where the resource
// segment is "type/id", "type:id", "type", or (S3) a bare bucket/key. Returns ""
// for anything that is not a well-formed ARN with a non-empty resource segment.
func ResourceType(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	service, resource := parts[2], parts[5]
	if resource == "" {
		return ""
	}
	// S3 has no resource-type prefix: a "/" means an object key, else a bucket.
	if service == "s3" {
		if strings.Contains(resource, "/") {
			return "object"
		}
		return "bucket"
	}
	// The IAM account root arn:aws:iam::<acct>:root has no "type/id" shape.
	if resource == "root" {
		return "account"
	}
	// Otherwise the type is the segment before the first "/" or ":" separator.
	if i := strings.IndexAny(resource, "/:"); i >= 0 {
		return resource[:i]
	}
	return resource
}
