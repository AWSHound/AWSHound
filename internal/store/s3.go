package store

import "github.com/AWSHound/AWSHound/internal/model"

// s3Service is the resource-bag key for S3 data. It matches S3Collector.Service().
const s3Service = "s3"

// s3AccountPABKey is the fixed resource-bag key under which an account-level Block
// Public Access config is stored. It is not an ARN, but the s3 bag is separate from
// bucket ARNs (which all start with "arn:aws:s3:::"), so it cannot collide; typed
// accessors below discriminate by concrete type regardless of key.
const s3AccountPABKey = "s3:account-public-access-block"

// IngestS3 stores an S3 payload on the given account: every bucket lands in the
// generic resource bag keyed by its ARN, and every bucket ARN plus every object ARN
// (arn:aws:s3:::<bucket>/<key>) is interned into the shared ARN universe so the
// evaluator can resolve S3 resource-pattern permissions. It is the in-memory port
// of AWSHound's add_s3_data / ingest_s3 (core/models/_queries/s3.py), minus the
// DuckDB-specific delete-then-insert replacement semantics.
//
// Objects are kept nested inside their bucket (the node parser reads them from the
// bucket), so they are not stored as standalone resources — only their ARNs are
// interned. The account-level Block Public Access config, when present, is stored
// under a fixed key so a future edge processor can read it via
// S3AccountPublicAccessBlock.
func IngestS3(st *Store, accountID string, data *model.S3Data) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)

	for i := range data.Buckets {
		b := &data.Buckets[i]
		arn := b.Arn
		if arn == "" {
			if b.Name == "" {
				continue
			}
			arn = "arn:aws:s3:::" + b.Name
		}
		acct.PutResource(s3Service, arn, b)
		st.ARN().Intern(arn)
		// Object ARNs are deliberately NOT interned into the evaluation universe
		// (§4 of docs/authorization-tensor.md): they scale with data volume, not
		// policy structure, and were the ARN universe's memory ceiling. Object
		// nodes and bucket->object containment edges are built from b.Objects
		// directly, and per-object authorization checks fall back to regex pattern
		// matching in CanPerformAction, so eviction bounds the universe without
		// changing graph output.
	}

	if data.AccountPublicAccessBlock != nil {
		acct.PutResource(s3Service, s3AccountPABKey, data.AccountPublicAccessBlock)
	}
}

// S3BucketList returns the buckets ingested on this account (each with its nested
// objects), ordered by ARN. The account-level Block Public Access config sharing the
// bag is filtered out by the type assertion.
func (a *Account) S3BucketList() []*model.S3Bucket {
	return listResources[model.S3Bucket](a, s3Service)
}

// S3AccountPublicAccessBlock returns the account-level Block Public Access config,
// or nil when none was ingested (the current Go collector never sets it — see
// IngestS3 and internal/model/s3.go).
func (a *Account) S3AccountPublicAccessBlock() *model.PublicAccessBlockConfiguration {
	for _, v := range a.Resources(s3Service) {
		if p, ok := v.(*model.PublicAccessBlockConfiguration); ok {
			return p
		}
	}
	return nil
}
