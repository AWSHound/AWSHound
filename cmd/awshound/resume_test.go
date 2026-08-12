package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/AWSHound/AWSHound/internal/store"
)

// nopReporter satisfies progress.Reporter for tests without touching the display.
type nopReporter struct{}

func (nopReporter) Stage(string, int) {}
func (nopReporter) AddTotal(int)      {}
func (nopReporter) Advance(int)       {}
func (nopReporter) Log(string)        {}
func (nopReporter) Stop()             {}

// writeRaw writes dir/<account>/<service>.json, making parents.
func writeRaw(t *testing.T, root, account, service, content string) {
	t.Helper()
	dir := filepath.Join(root, account)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, service+".json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPlanResumeSkipsPresentUnitsPerService(t *testing.T) {
	root := t.TempDir()
	const acct = "111122223333"
	// iam is complete on disk; ec2 was left truncated by a killed run; s3 was never
	// reached (no file). Resume must keep iam, re-fetch ec2 and s3.
	writeRaw(t, root, acct, "iam", `{"UserDetailList":[],"GroupDetailList":[],"RoleDetailList":[],"Policies":[]}`)
	writeRaw(t, root, acct, "ec2", `{"AccountId":"111122223333","Instances":[`)

	s := store.New()
	boots := []bootedSession{{accountID: acct, collectors: []string{"iam", "ec2", "s3"}}}

	resumed := planResume(boots, root, s, nopReporter{}, false)

	if want := []string{"iam"}; !reflect.DeepEqual(resumed, want) {
		t.Errorf("resumed = %v, want %v", resumed, want)
	}
	if want := []string{"ec2", "s3"}; !reflect.DeepEqual(boots[0].collectors, want) {
		t.Errorf("remaining collectors = %v, want %v (per-service resume)", boots[0].collectors, want)
	}
	// The completed unit must have been folded into the store.
	var found bool
	for _, a := range s.Accounts() {
		if a.ID == acct {
			found = true
		}
	}
	if !found {
		t.Errorf("resumed iam unit was not ingested for account %s", acct)
	}
}

func TestPlanResumeMissingUnitAndAccountDirCollectsEverything(t *testing.T) {
	root := t.TempDir()
	// No raw directory at all for this account → a fresh --resume run degrades to a
	// full collection, never silently skipping the account.
	boots := []bootedSession{{accountID: "999988887777", collectors: []string{"iam", "s3"}}}

	resumed := planResume(boots, root, store.New(), nopReporter{}, false)

	if len(resumed) != 0 {
		t.Errorf("resumed = %v, want none", resumed)
	}
	if want := []string{"iam", "s3"}; !reflect.DeepEqual(boots[0].collectors, want) {
		t.Errorf("collectors = %v, want %v (nothing on disk)", boots[0].collectors, want)
	}
}

func TestWriteRawFileIsAtomicAndValid(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "acct")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ec2.json")
	if err := writeRawFile(path, map[string]any{"AccountId": "111", "Instances": []any{}}); err != nil {
		t.Fatalf("writeRawFile: %v", err)
	}
	// The final file must exist as a completed unit resume recognizes as ec2.
	if !resumeUnit(store.New(), path, "ec2") {
		t.Fatalf("written file is not recognized as a completed ec2 unit")
	}
	// ...and no temp file may be left behind in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ec2.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory contents = %v, want only [ec2.json] (no temp leftovers)", names)
	}
}

func TestPlanResumeStorelessSkipsPresentUnits(t *testing.T) {
	// The `collect` path passes a nil store: resume must skip completed units by
	// validity alone (no ingest), and still re-fetch a truncated one.
	root := t.TempDir()
	const acct = "555566667777"
	writeRaw(t, root, acct, "iam", `{"UserDetailList":[],"GroupDetailList":[],"RoleDetailList":[],"Policies":[]}`)
	writeRaw(t, root, acct, "ec2", `{"AccountId":"555566667777","Instances":[`) // truncated

	boots := []bootedSession{{accountID: acct, collectors: []string{"iam", "ec2", "s3"}}}

	resumed := planResume(boots, root, nil, nopReporter{}, false)

	if want := []string{"iam"}; !reflect.DeepEqual(resumed, want) {
		t.Errorf("resumed = %v, want %v", resumed, want)
	}
	if want := []string{"ec2", "s3"}; !reflect.DeepEqual(boots[0].collectors, want) {
		t.Errorf("remaining collectors = %v, want %v", boots[0].collectors, want)
	}
}

func TestPlanResumeEmptyFileReFetches(t *testing.T) {
	root := t.TempDir()
	const acct = "222233334444"
	// Zero-byte file (a common half-written artifact) must not count as collected.
	writeRaw(t, root, acct, "s3", ``)

	boots := []bootedSession{{accountID: acct, collectors: []string{"s3"}}}
	resumed := planResume(boots, root, store.New(), nopReporter{}, false)

	if len(resumed) != 0 {
		t.Errorf("resumed = %v, want none (empty file)", resumed)
	}
	if want := []string{"s3"}; !reflect.DeepEqual(boots[0].collectors, want) {
		t.Errorf("collectors = %v, want %v", boots[0].collectors, want)
	}
}
