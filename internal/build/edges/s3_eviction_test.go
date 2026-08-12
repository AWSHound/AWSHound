package edges_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build/edges"
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// Object ARNs are no longer interned into the evaluation universe (§4 eviction),
// yet per-object S3 edges must still be emitted: the S3 family enumerates objects
// from the bucket's object list and CanPerformAction falls back to regex pattern
// matching for the (un-interned) object ARN. This locks that eviction is
// output-preserving for object-target edges.
func TestS3ObjectEdgesSurviveEviction(t *testing.T) {
	acct := "111122223333"
	alice := "arn:aws:iam::111122223333:user/alice"
	objARN := "arn:aws:s3:::data-bucket/reports/q1.csv"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data-bucket/*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
	})
	store.IngestS3(s, acct, &model.S3Data{
		Buckets: []model.S3Bucket{{
			Name: "data-bucket", Arn: "arn:aws:s3:::data-bucket",
			Objects: []model.S3Object{{Key: "reports/q1.csv"}},
		}},
	})

	// Eviction invariant: the object ARN is a graph endpoint but NOT in the universe.
	if _, interned := s.ARN().ID(objARN); interned {
		t.Fatalf("object ARN must not be interned into the eval universe after §4 eviction")
	}

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}
	var found, bucketFound bool
	bucketARN := "arn:aws:s3:::data-bucket"
	for _, e := range edges.S3Edges(s, pe) {
		if e.Start == alice && e.End == objARN && e.Kind == graph.KindCanGetObject {
			found = true
		}
		// Bucket-scoped constituents are now generated via the scan driver.
		if e.Start == alice && e.End == bucketARN && e.Kind == graph.KindCanGetObject {
			// (GetObject targets objects, not the bucket; ignore.)
			_ = e
		}
	}
	if !found {
		t.Fatalf("expected alice -[AWS_CanGetObject]-> %s despite eviction (regex fallback)", objARN)
	}

	// A bucket-scoped action (ListBucket) must surface via the migrated scan-driver path.
	doc2 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`
	s2 := store.New()
	s2.AddAuthDetails(acct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: alice, UserName: "alice",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc2}}}},
	})
	store.IngestS3(s2, acct, &model.S3Data{
		Buckets: []model.S3Bucket{{Name: "data-bucket", Arn: bucketARN}},
	})
	pe2, err := eval.NewPolicyEvaluator(s2)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edges.S3Edges(s2, pe2) {
		if e.Start == alice && e.End == bucketARN && e.Kind == graph.KindCanListBucket {
			bucketFound = true
		}
	}
	if !bucketFound {
		t.Fatalf("expected alice -[AWS_CanListBucket]-> %s via the scan-driver bucket path", bucketARN)
	}
}
