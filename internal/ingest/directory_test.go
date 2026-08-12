package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AWSHound/AWSHound/internal/store"
)

type noopReporter struct{}

func (noopReporter) Stage(string, int) {}
func (noopReporter) AddTotal(int)      {}
func (noopReporter) Advance(int)       {}
func (noopReporter) Log(string)        {}
func (noopReporter) Stop()             {}

// write creates dir/name (making parents) with the given JSON content.
func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryClassifiesRecursivelyAndAttributesAccounts(t *testing.T) {
	root := t.TempDir()

	// GAAD: account comes from the principal ARN.
	write(t, root, "111122223333/iam.json", `{
		"UserDetailList": [], "GroupDetailList": [],
		"RoleDetailList": [{"Arn":"arn:aws:iam::111122223333:role/app","RoleName":"app"}],
		"Policies": []
	}`)
	// EC2 with an explicit AccountId in the payload.
	write(t, root, "444455556666/ec2.json", `{"AccountId":"444455556666","Instances":[]}`)
	// EC2 with NO AccountId — must fall back to the 12-digit path component.
	write(t, root, "777788889999/nested/ec2.json", `{"Instances":[]}`)
	// KMS, explicit account.
	write(t, root, "444455556666/kms.json", `{"AccountId":"444455556666","Keys":[]}`)
	// Unrecognized shape → skipped, not an error.
	write(t, root, "notes/readme.json", `{"hello":"world"}`)
	// Non-JSON file → ignored by the walk.
	write(t, root, "444455556666/notes.txt", `ignore me`)

	s := store.New()
	res, err := Directory(s, root, noopReporter{}, nil)
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}

	if res.Files != 5 {
		t.Errorf("Files = %d, want 5 (the .json files)", res.Files)
	}
	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (readme.json)", res.Skipped)
	}
	if res.Counts["iam"] != 1 || res.Counts["ec2"] != 2 || res.Counts["kms"] != 1 {
		t.Errorf("Counts = %v, want iam:1 ec2:2 kms:1", res.Counts)
	}

	got := map[string]bool{}
	for _, a := range s.Accounts() {
		got[a.ID] = true
	}
	for _, want := range []string{"111122223333", "444455556666", "777788889999"} {
		if !got[want] {
			t.Errorf("account %s missing from store; have %v", want, got)
		}
	}
}

func TestDirectoryReadFailureIsLoud(t *testing.T) {
	root := t.TempDir()
	// Recognized shape but malformed JSON body → must error, not skip.
	write(t, root, "acct/ec2.json", `{"Instances": [ this is not json ]}`)

	s := store.New()
	if _, err := Directory(s, root, noopReporter{}, nil); err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestDirectoryEmpty(t *testing.T) {
	s := store.New()
	res, err := Directory(s, t.TempDir(), noopReporter{}, nil)
	if err != nil {
		t.Fatalf("Directory: %v", err)
	}
	if res.Files != 0 || len(res.Services()) != 0 {
		t.Errorf("empty dir should yield no files/services, got %+v", res)
	}
}

func TestIngestWorkersUsesMemorySafeDefaultAndOverride(t *testing.T) {
	t.Setenv("GOAWSHOUND_INGEST_WORKERS", "")
	if got := ingestWorkers(100); got != defaultIngestWorkers {
		t.Fatalf("default ingest workers = %d, want %d", got, defaultIngestWorkers)
	}
	if got := ingestWorkers(1); got != 1 {
		t.Fatalf("single file workers = %d, want 1", got)
	}

	t.Setenv("GOAWSHOUND_INGEST_WORKERS", "5")
	if got := ingestWorkers(100); got != 5 {
		t.Fatalf("override ingest workers = %d, want 5", got)
	}
	if got := ingestWorkers(3); got != 3 {
		t.Fatalf("override must cap at file count: got %d, want 3", got)
	}

	for _, invalid := range []string{"0", "-2", "not-a-number"} {
		t.Setenv("GOAWSHOUND_INGEST_WORKERS", invalid)
		if got := ingestWorkers(100); got != defaultIngestWorkers {
			t.Errorf("invalid override %q yielded %d workers, want safe default %d", invalid, got, defaultIngestWorkers)
		}
	}
}
