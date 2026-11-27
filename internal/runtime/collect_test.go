package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// TestIngestDataDispatches confirms IngestData routes a raw fetch payload to the
// right typed store ingest — the in-memory path the `all` command uses so it can
// write raw/ without reading it back.
func TestIngestDataDispatches(t *testing.T) {
	s := store.New()

	gaad := &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: "arn:aws:iam::111122223333:user/alice", UserName: "alice"},
		},
	}
	if err := IngestData(s, "111122223333", "iam", gaad); err != nil {
		t.Fatalf("iam: %v", err)
	}
	if u := s.Account("111122223333").Users["arn:aws:iam::111122223333:user/alice"]; u == nil {
		t.Error("iam user not ingested via IngestData")
	}

	ec2 := &model.EC2Data{
		AccountId: "444455556666",
		Instances: []model.EC2Instance{{InstanceId: "i-abc", Region: "us-east-1"}},
	}
	if err := IngestData(s, "444455556666", "ec2", ec2); err != nil {
		t.Fatalf("ec2: %v", err)
	}
	if got := s.Account("444455556666").EC2InstanceList(); len(got) != 1 || got[0].InstanceId != "i-abc" {
		t.Errorf("ec2 instance not ingested via IngestData: %+v", got)
	}
}

func TestIngestDataUnknownService(t *testing.T) {
	if err := IngestData(store.New(), "111122223333", "bogus", &model.EC2Data{}); err == nil {
		t.Fatal("expected error for unknown service")
	}
}

func TestIngestDataTypeMismatch(t *testing.T) {
	// ec2 service with a GAAD payload → type assertion must fail, not panic.
	if err := IngestData(store.New(), "111122223333", "ec2", &model.AuthDetails{}); err == nil {
		t.Fatal("expected error for mismatched payload type")
	}
}

func TestIngestDataFilteredAppliesS3FilterWithoutMutatingRaw(t *testing.T) {
	filterPath := filepath.Join(t.TempDir(), "filter.json")
	filterJSON := `{
		"version": 1,
		"default": "include",
		"max_objects_per_bucket": 1,
		"rules": [
			{"action": "exclude", "target": "bucket", "match": {"name": {"contains": "cloudtrail"}}}
		]
	}`
	if err := os.WriteFile(filterPath, []byte(filterJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := model.LoadS3Filter(filterPath)
	if err != nil {
		t.Fatalf("LoadS3Filter: %v", err)
	}

	raw := &model.S3Data{
		AccountId: "111122223333",
		Buckets: []model.S3Bucket{
			{
				Name: "org-cloudtrail-logs",
				Arn:  "arn:aws:s3:::org-cloudtrail-logs",
				Objects: []model.S3Object{
					{Key: "log1.json.gz"},
				},
			},
			{
				Name: "app-data",
				Arn:  "arn:aws:s3:::app-data",
				Objects: []model.S3Object{
					{Key: "a.txt"},
					{Key: "b.txt"},
				},
			},
		},
	}

	s := store.New()
	if err := IngestDataFiltered(s, "111122223333", "s3", raw, cfg); err != nil {
		t.Fatalf("IngestDataFiltered: %v", err)
	}

	got := s.Account("111122223333").S3BucketList()
	if len(got) != 1 || got[0].Name != "app-data" {
		t.Fatalf("ingested buckets = %+v, want only [app-data]", got)
	}
	if len(got[0].Objects) != 1 || got[0].Objects[0].Key != "a.txt" {
		t.Fatalf("ingested objects = %+v, want only [a.txt]", got[0].Objects)
	}

	// Raw payload must remain unmodified so writeRawFile persists all buckets/objects.
	if len(raw.Buckets) != 2 || len(raw.Buckets[1].Objects) != 2 {
		t.Fatalf("raw S3Data was mutated by IngestDataFiltered: %+v", raw)
	}
}
