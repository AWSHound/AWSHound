package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCollectErrorLogConcurrentRecordAndCounts(t *testing.T) {
	l := NewCollectErrorLog()
	var wg sync.WaitGroup
	// 3 services × 10 goroutines each, recording concurrently.
	for _, svc := range []string{"organizations", "s3", "iam"} {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(svc string) {
				defer wg.Done()
				l.Record(CollectError{AccountID: "111122223333", Service: svc, Message: "boom"})
			}(svc)
		}
	}
	wg.Wait()

	if got := l.Len(); got != 30 {
		t.Fatalf("Len() = %d, want 30", got)
	}
	counts := l.CountsByService()
	for _, svc := range []string{"organizations", "s3", "iam"} {
		if counts[svc] != 10 {
			t.Errorf("CountsByService()[%q] = %d, want 10", svc, counts[svc])
		}
	}
	// SummaryByService is ordered by service name.
	if got, want := l.SummaryByService(), "iam:10, organizations:10, s3:10"; got != want {
		t.Errorf("SummaryByService() = %q, want %q", got, want)
	}
}

func TestCollectErrorLogWriteJSON(t *testing.T) {
	l := NewCollectErrorLog()
	l.Record(CollectError{AccountID: "111122223333", Profile: "acct-a", Service: "organizations", Message: "AccessDenied"})
	l.Record(CollectError{AccountID: "444455556666", Profile: "acct-b", Service: "organizations", Message: "AccessDenied"})
	l.Record(CollectError{AccountID: "111122223333", Profile: "acct-a", Service: "s3", Message: "Throttled"})

	path := filepath.Join(t.TempDir(), "collect-errors.json")
	if err := l.WriteJSON(path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var report collectErrorReport
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if report.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Total)
	}
	if report.ByService["organizations"] != 2 || report.ByService["s3"] != 1 {
		t.Errorf("ByService = %v, want organizations:2 s3:1", report.ByService)
	}
	if len(report.Errors) != 3 {
		t.Errorf("Errors len = %d, want 3", len(report.Errors))
	}
}

func TestCollectErrorLogWriteJSONNoErrorsIsNoop(t *testing.T) {
	l := NewCollectErrorLog()
	path := filepath.Join(t.TempDir(), "collect-errors.json")
	if err := l.WriteJSON(path); err != nil {
		t.Fatalf("WriteJSON on empty log: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected no file written for empty log, stat err = %v", err)
	}
}

func TestCollectErrorLogNilReceiver(t *testing.T) {
	var l *CollectErrorLog
	l.Record(CollectError{Service: "iam", Message: "x"}) // must not panic
	if l.Len() != 0 {
		t.Errorf("nil Len() = %d, want 0", l.Len())
	}
	if err := l.WriteJSON(filepath.Join(t.TempDir(), "x.json")); err != nil {
		t.Errorf("nil WriteJSON: %v", err)
	}
}
