package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/collect"
	"github.com/AWSHound/AWSHound/internal/runtime"
)

type recordingReporter struct {
	logs []string
}

func (*recordingReporter) Stage(string, int) {}
func (*recordingReporter) AddTotal(int)      {}
func (*recordingReporter) Advance(int)       {}
func (r *recordingReporter) Log(msg string)  { r.logs = append(r.logs, msg) }
func (*recordingReporter) Stop()             {}

func TestBootstrapErrorsAreSilentAndCollectedOutsideVerboseMode(t *testing.T) {
	reporter := &recordingReporter{}
	errLog := runtime.NewCollectErrorLog()
	targets := []accountTarget{{
		label: "893871155819",
		newSession: func(context.Context, string) (*collect.Session, error) {
			return nil, errors.New("sts:AssumeRole: AccessDenied")
		},
	}}

	boots := bootstrapAccounts(context.Background(), targets, nil, 1, reporter, false, nil, errLog)
	if len(boots) != 0 {
		t.Fatalf("bootstrapped %d accounts, want 0", len(boots))
	}
	if len(reporter.logs) != 1 || !strings.Contains(reporter.logs[0], "no accounts could be bootstrapped") {
		t.Fatalf("non-verbose bootstrap should only report the concise terminal message; got %q", reporter.logs)
	}

	path := filepath.Join(t.TempDir(), "collect-errors.json")
	if err := errLog.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{`"account_id": "893871155819"`, `"service": "bootstrap"`, `sts:AssumeRole: AccessDenied`} {
		if !strings.Contains(got, want) {
			t.Errorf("bootstrap error report missing %q; got:\n%s", want, got)
		}
	}
}
