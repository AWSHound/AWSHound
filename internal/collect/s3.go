package collect

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/AWSHound/AWSHound/internal/model"
)

// defaultMaxObjectsPerBucket bounds per-bucket object listing, matching
// S3Collector.fetch's max_objects_per_bucket default (1000). The Python threads a
// configurable value (and an --s3-filter) through the CLI; here it is a package
// constant until that config is wired.
const defaultMaxObjectsPerBucket = 1000

// S3Collector fetches S3 bucket (and bounded object) data for the session account
// (a global collector; see the package doc).
//
// S3 ListBuckets is a GLOBAL call — one request returns every bucket regardless of
// region — so this is not the per-region fan-out the region-scoped collectors use.
// Instead each bucket's region is resolved via GetBucketLocation, then every
// per-bucket control-plane call is routed to that region through a per-call Options
// override (s3RegionOptFn), avoiding S3's cross-region 301 redirects.
type S3Collector struct{}

// Service returns the collector's service identifier.
func (S3Collector) Service() string { return "s3" }

// Fetch lists all buckets, resolves each bucket's region and control-plane data
// (policy, ACL, public-access-block, ownership controls, tags) plus a bounded slice
// of objects, and returns them as *model.S3Data. It mirrors S3Collector.fetch.
//
// Per-bucket sub-calls that fail (commonly AccessDenied, or NoSuchBucketPolicy for
// buckets without a policy) are swallowed to a zero value, exactly as the Python's
// per-call try/except does, so one restricted bucket never fails the whole account.
func (S3Collector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.limiter.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.limiter.release()
	defer s.tick()

	// Base client for the global ListBuckets + GetBucketLocation calls. regionCfg
	// supplies the default endpoint region when the session has none resolved.
	client := s3.NewFromConfig(s.regionCfg(""))

	var buckets []model.S3Bucket
	pager := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		// Each bucket is many sequential per-bucket calls (region, policy, ACL,
		// PAB, ownership, tags, objects). Count them into the progress denominator
		// and tick once per bucket below so the S3 collector's tail advances
		// visibly instead of sitting on its single completion tick — the per-bucket
		// helpers never return an error, so every added unit is ticked. See
		// Session.addWork.
		s.addWork(len(page.Buckets))
		for _, rb := range page.Buckets {
			// ListBuckets always returns a bucket name, so it is used directly.
			name := aws.ToString(rb.Name)
			region := s3BucketLocation(ctx, client, name)
			buckets = append(buckets, model.S3Bucket{
				Name:              name,
				Arn:               "arn:aws:s3:::" + name,
				CreationDate:      formatTime(rb.CreationDate),
				Region:            region,
				BucketPolicy:      s3BucketPolicy(ctx, client, name, region),
				Acl:               s3BucketACL(ctx, client, name, region),
				PublicAccessBlock: s3BucketPAB(ctx, client, name, region),
				OwnershipControls: s3OwnershipControls(ctx, client, name, region),
				Tags:              s3BucketTagging(ctx, client, name, region),
				Objects:           s3ListObjects(ctx, client, name, region, defaultMaxObjectsPerBucket),
			})
			s.tick()
		}
	}

	// AccountPublicAccessBlock (s3control:GetPublicAccessBlock by account id) is not
	// collected: this build provisions only service/s3, not service/s3control. The
	// field stays nil; see internal/model/s3.go.
	return &model.S3Data{
		AccountId: accountID,
		Buckets:   buckets,
	}, nil
}

// s3RegionOptFn returns a per-call Options override that pins a request to a
// bucket's region, so control-plane calls avoid S3's cross-region 301 redirect.
func s3RegionOptFn(region string) func(*s3.Options) {
	return func(o *s3.Options) {
		if region != "" {
			o.Region = region
		}
	}
}

// s3BucketLocation resolves a bucket's region via GetBucketLocation. A null/empty
// LocationConstraint means us-east-1, and any error falls back to us-east-1 —
// matching _get_bucket_location.
func s3BucketLocation(ctx context.Context, client *s3.Client, name string) string {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(name)})
	if err != nil {
		return "us-east-1"
	}
	if region := string(out.LocationConstraint); region != "" {
		return region
	}
	return "us-east-1"
}

// s3BucketPolicy returns the raw bucket policy JSON document, or nil when the
// bucket has no policy (NoSuchBucketPolicy) or the call is denied. Port of
// _get_bucket_policy (which json.loads'd the document; here the opaque JSON is kept
// verbatim and re-encoded at node-build time).
func s3BucketPolicy(ctx context.Context, client *s3.Client, name, region string) json.RawMessage {
	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(name)}, s3RegionOptFn(region))
	if err != nil || out.Policy == nil {
		return nil
	}
	policy := aws.ToString(out.Policy)
	if policy == "" {
		return nil
	}
	return json.RawMessage(policy)
}

// s3BucketACL returns the bucket ACL (owner + grants), or nil on error. Port of
// _get_bucket_acl.
func s3BucketACL(ctx context.Context, client *s3.Client, name, region string) *model.BucketACL {
	out, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(name)}, s3RegionOptFn(region))
	if err != nil {
		return nil
	}
	acl := &model.BucketACL{}
	if out.Owner != nil {
		acl.Owner = &model.ACLOwner{
			DisplayName: aws.ToString(out.Owner.DisplayName),
			ID:          aws.ToString(out.Owner.ID),
		}
	}
	for _, g := range out.Grants {
		grant := model.ACLGrant{Permission: string(g.Permission)}
		if g.Grantee != nil {
			grant.Grantee = &model.ACLGrantee{
				Type:         string(g.Grantee.Type),
				DisplayName:  aws.ToString(g.Grantee.DisplayName),
				EmailAddress: aws.ToString(g.Grantee.EmailAddress),
				ID:           aws.ToString(g.Grantee.ID),
				URI:          aws.ToString(g.Grantee.URI),
			}
		}
		acl.Grants = append(acl.Grants, grant)
	}
	return acl
}

// s3BucketPAB returns the bucket's Block Public Access config, or nil when unset or
// on error. Port of _get_public_access_block.
func s3BucketPAB(ctx context.Context, client *s3.Client, name, region string) *model.PublicAccessBlockConfiguration {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)}, s3RegionOptFn(region))
	if err != nil || out.PublicAccessBlockConfiguration == nil {
		return nil
	}
	c := out.PublicAccessBlockConfiguration
	return &model.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.ToBool(c.BlockPublicAcls),
		IgnorePublicAcls:      aws.ToBool(c.IgnorePublicAcls),
		BlockPublicPolicy:     aws.ToBool(c.BlockPublicPolicy),
		RestrictPublicBuckets: aws.ToBool(c.RestrictPublicBuckets),
	}
}

// s3OwnershipControls returns the first ownership rule's ObjectOwnership value
// (e.g. "BucketOwnerEnforced"), or "" when unset or on error. Port of
// _get_ownership_controls.
func s3OwnershipControls(ctx context.Context, client *s3.Client, name, region string) string {
	out, err := client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: aws.String(name)}, s3RegionOptFn(region))
	if err != nil || out.OwnershipControls == nil {
		return ""
	}
	rules := out.OwnershipControls.Rules
	if len(rules) == 0 {
		return ""
	}
	return string(rules[0].ObjectOwnership)
}

// s3BucketTagging returns the bucket's tag set, or nil when untagged or on error.
// Port of _get_bucket_tagging (S3 raises NoSuchTagSet for untagged buckets).
func s3BucketTagging(ctx context.Context, client *s3.Client, name, region string) []model.Tag {
	out, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(name)}, s3RegionOptFn(region))
	if err != nil {
		return nil
	}
	var tags []model.Tag
	for _, t := range out.TagSet {
		tags = append(tags, model.Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
	}
	return tags
}

// s3ListObjects lists up to max objects from a bucket via the ListObjectsV2
// paginator, stopping as soon as the cap is reached. Port of _list_objects; the
// paginator's page limit caps keys per page, while the max here caps the total
// (matching the Python's len(objects) >= max_objects break). Errors return whatever
// was collected so far.
func s3ListObjects(ctx context.Context, client *s3.Client, name, region string, maxObjects int) []model.S3Object {
	if maxObjects <= 0 {
		return nil
	}
	var objects []model.S3Object
	pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: aws.String(name)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx, s3RegionOptFn(region))
		if err != nil {
			return objects
		}
		for _, o := range page.Contents {
			storageClass := string(o.StorageClass)
			if storageClass == "" {
				storageClass = "STANDARD"
			}
			objects = append(objects, model.S3Object{
				Key:          aws.ToString(o.Key),
				Size:         aws.ToInt64(o.Size),
				LastModified: formatTime(o.LastModified),
				StorageClass: storageClass,
				ETag:         aws.ToString(o.ETag),
			})
			if len(objects) >= maxObjects {
				return objects
			}
		}
	}
	return objects
}
