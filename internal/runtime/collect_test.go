package runtime

import (
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
