package progress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newToFile returns a Tracker writing to a fresh temp file (never a terminal, so
// the deterministic piped-output path is exercised) plus the file path to read
// back what was rendered.
func newToFile(t *testing.T) (*Tracker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return New(f), path
}

func TestTrackerReachesCompletion(t *testing.T) {
	tr, path := newToFile(t)
	tr.Stage("Collect", 4)
	for i := 0; i < 4; i++ {
		tr.Advance(1)
	}
	tr.Stop() // final render bypasses the throttle, so 100% is guaranteed to print

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "Collect") {
		t.Errorf("output missing stage name; got:\n%s", got)
	}
	if !strings.Contains(got, "100%") || !strings.Contains(got, "(4/4)") {
		t.Errorf("output did not reach 100%% (4/4); got:\n%s", got)
	}
}

// TestTrackerAddTotalReachesCompletion mirrors how a global collector reports
// finer-grained tail progress: the stage starts with the pre-counted single unit,
// then AddTotal grows the denominator as sub-work is discovered and each added
// unit is matched by an Advance. The stage must still finish at an honest 100%
// over the enlarged total.
func TestTrackerAddTotalReachesCompletion(t *testing.T) {
	tr, path := newToFile(t)
	tr.Stage("Collect", 1) // one pre-counted global unit
	tr.AddTotal(5)         // 5 buckets/pages/policies discovered
	for i := 0; i < 5; i++ {
		tr.Advance(1) // one tick per sub-item
	}
	tr.Advance(1) // the collector's own completion tick
	tr.Stop()

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "100%") || !strings.Contains(got, "(6/6)") {
		t.Errorf("AddTotal stage did not reach 100%% (6/6); got:\n%s", got)
	}
}

// TestTrackerAddTotalNonPositiveNoOp guards the addWork(n<=0) contract so a
// collector that discovered no sub-work neither shrinks nor corrupts the total.
func TestTrackerAddTotalNonPositiveNoOp(t *testing.T) {
	tr, _ := newToFile(t)
	tr.Stage("Collect", 4)
	tr.AddTotal(0)
	tr.AddTotal(-3)
	if got := tr.total.Load(); got != 4 {
		t.Errorf("total changed by non-positive AddTotal: got %d, want 4", got)
	}
	tr.Stop()
}

func TestTrackerStopIdempotent(t *testing.T) {
	tr, _ := newToFile(t)
	tr.Stage("Bootstrap", 2)
	tr.Advance(2)
	tr.Stop()
	tr.Stop() // must not panic (double close guarded by sync.Once)
}

func TestTrackerIndeterminateStage(t *testing.T) {
	tr, path := newToFile(t)
	tr.Stage("Emit", 0) // no total → no percentage, just a count
	tr.Stop()

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "Emit") {
		t.Errorf("output missing indeterminate stage name; got:\n%s", got)
	}
	if strings.Contains(got, "%") {
		t.Errorf("indeterminate stage should not show a percentage; got:\n%s", got)
	}
}

// Both reporters must satisfy the Reporter interface the pipeline depends on.
var (
	_ Reporter = (*Tracker)(nil)
	_ Reporter = (*Logger)(nil)
)

func TestLoggerLogsStagesAndCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	l := NewLogger(f)
	l.Stage("Collect", 3)
	l.Advance(1)
	l.Advance(1)
	l.Advance(1)
	l.Detail("building %s node %s", "AWS_User", "arn:aws:iam::123456789012:user/alice")
	l.Log("collector s3 (profile prod): denied")
	l.Stop()

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"▶ Collect (0/3)",             // stage start
		"Collect 3/3 (100%)",          // progress reached 100%
		"✔ Collect done (3/3)",        // completion line
		"building AWS_User node",      // current-work detail survives
		"collector s3 (profile prod)", // out-of-band Log message survives
	} {
		if !strings.Contains(got, want) {
			t.Errorf("logger output missing %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "[") == false {
		t.Errorf("logger lines should be timestamped; got:\n%s", got)
	}
}

func TestLoggerStopIdempotent(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "l.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	l := NewLogger(f)
	l.Stage("Bootstrap", 1)
	l.Advance(1)
	l.Stop()
	l.Stop() // must not panic
}

// TestClampWidth guards the one-row clamp that stops a wide progress line from
// wrapping (which would make the carriage-return redraw stack copies of the bar).
func TestClampWidth(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"hello", 0, "hello"},  // unknown width: no-op
		{"hello", -1, "hello"}, // negative width: no-op
		{"hello", 10, "hello"}, // fits: unchanged
		{"hello", 5, "hello"},  // exactly fits
		{"hello", 3, "hel"},    // truncated to width columns
		{"████░░", 3, "███"},   // multibyte cells cut on a rune boundary
		{"ab⠋cd", 3, "ab⠋"},    // braille spinner counts as one column
	}
	for _, c := range cases {
		if got := clampWidth(c.in, c.width); got != c.want {
			t.Errorf("clampWidth(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
	}
}

func TestPctOf(t *testing.T) {
	cases := []struct {
		cur, tot int64
		want     int
	}{
		{0, 0, 0},   // indeterminate
		{1, 0, 0},   // guard against divide-by-zero
		{0, 10, 0},  //
		{5, 10, 50}, //
		{10, 10, 100},
		{15, 10, 100}, // clamped
	}
	for _, c := range cases {
		if got := pctOf(c.cur, c.tot); got != c.want {
			t.Errorf("pctOf(%d,%d) = %d, want %d", c.cur, c.tot, got, c.want)
		}
	}
}
