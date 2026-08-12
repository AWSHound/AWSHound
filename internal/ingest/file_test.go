package ingest

import (
	"path/filepath"
	"testing"

	"github.com/AWSHound/AWSHound/internal/store"
)

func TestFileIngestsAndClassifiesOne(t *testing.T) {
	root := t.TempDir()
	write(t, root, "444455556666/ec2.json", `{"AccountId":"444455556666","Instances":[]}`)

	s := store.New()
	svc, err := File(s, filepath.Join(root, "444455556666", "ec2.json"), nil)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if svc != "ec2" {
		t.Errorf("service = %q, want ec2", svc)
	}
	// The account must have landed in the store.
	var found bool
	for _, a := range s.Accounts() {
		if a.ID == "444455556666" {
			found = true
		}
	}
	if !found {
		t.Errorf("account 444455556666 not ingested into store")
	}
}

func TestFileUnrecognizedShapeReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	write(t, root, "notes.json", `{"hello":"world"}`)

	svc, err := File(store.New(), filepath.Join(root, "notes.json"), nil)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if svc != "" {
		t.Errorf("service = %q, want \"\" for unrecognized shape", svc)
	}
}

func TestClassifyFileValidatesWithoutIngest(t *testing.T) {
	root := t.TempDir()
	write(t, root, "444455556666/ec2.json", `{"AccountId":"444455556666","Instances":[]}`)
	// Truncated after the discriminator key — detectService alone would return "ec2"
	// and miss it, so ClassifyFile must reject it via the json.Valid check.
	write(t, root, "acct/ec2.json", `{"Instances":[`)
	write(t, root, "notes.json", `{"hello":"world"}`)

	if svc, err := ClassifyFile(filepath.Join(root, "444455556666", "ec2.json")); err != nil || svc != "ec2" {
		t.Errorf("ClassifyFile(valid) = %q, %v; want ec2, nil", svc, err)
	}
	if _, err := ClassifyFile(filepath.Join(root, "acct", "ec2.json")); err == nil {
		t.Error("ClassifyFile(truncated) = nil error; want error")
	}
	if svc, err := ClassifyFile(filepath.Join(root, "notes.json")); err != nil || svc != "" {
		t.Errorf("ClassifyFile(unrecognized) = %q, %v; want \"\", nil", svc, err)
	}
}

func TestFileTruncatedIsError(t *testing.T) {
	root := t.TempDir()
	// A recognized top-level key but a truncated body — what a kill mid-write can
	// leave. Resume must see this as an error so the unit is re-fetched.
	write(t, root, "acct/ec2.json", `{"AccountId":"111","Instances":[`)

	if _, err := File(store.New(), filepath.Join(root, "acct", "ec2.json"), nil); err == nil {
		t.Fatal("expected an error for truncated JSON, got nil")
	}
}
