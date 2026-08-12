// Package progress renders a single-line, stage-aware progress indicator for the
// awshound pipeline. One Tracker owns a background goroutine that redraws one
// line on a ticker, so the user always sees which stage is running, roughly how
// far through it is, and — via a live spinner — that the process is still alive.
//
// It adapts to its output: on a terminal it rewrites a single line in place
// (carriage return + clear-to-EOL) with a live spinner; when stderr is redirected
// to a file or pipe it emits throttled plain lines (no ANSI, no spinner) so logs
// stay readable. All methods are safe for concurrent use — collectors call
// Advance from many goroutines at once.
package progress

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Reporter is the progress sink the pipeline talks to. The interactive Tracker
// (a redrawn progress bar) and the verbose Logger (plain, timestamped lines) both
// implement it, so callers drive progress without caring which is in use. Its
// method set is a superset of runtime.BuildProgress, so a Reporter satisfies that
// interface too.
type Reporter interface {
	// Stage begins a named stage expecting total Advance units (0 = indeterminate).
	Stage(name string, total int)
	// AddTotal grows the current stage's expected unit count by n, for work only
	// discovered after the stage began (e.g. a global collector learning how many
	// buckets/pages/policies it must walk). n<=0 is a no-op. Pair it with the same
	// number of later Advance calls so the stage still finishes at 100%.
	AddTotal(n int)
	// Advance records that n units of the current stage completed.
	Advance(n int)
	// Log emits an out-of-band message (warning, per-item note) without corrupting
	// the display.
	Log(msg string)
	// Stop finalizes the display. Idempotent.
	Stop()
}

// Detailer is implemented by reporters that can surface verbose current-work
// descriptions. It remains separate from Reporter so existing progress sinks do
// not need to handle high-cardinality diagnostic output.
type Detailer interface {
	Detail(format string, args ...any)
}

// spinnerFrames animate to prove the renderer (and therefore the process) is
// alive even when a stage's count is momentarily static.
var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

const (
	renderInterval = 120 * time.Millisecond // redraw cadence / heartbeat
	barWidth       = 22                     // filled+empty cells in the bar
	nonTTYStepPct  = 10                     // piped: print at least every N%
	nonTTYStepGap  = 2 * time.Second        // piped: ...or every N seconds
)

// Tracker is a live progress display. Create with New, describe work with Stage,
// report completion with Advance, surface out-of-band messages with Log, and call
// Stop once when done.
type Tracker struct {
	w     *os.File
	isTTY bool

	current atomic.Int64
	total   atomic.Int64

	mu         sync.Mutex
	stage      string
	stageStart time.Time
	spin       int
	// non-TTY print throttle
	lastPct   int
	lastPrint time.Time

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// SetStageLabel changes only the text shown for the active stage. Unlike Stage,
// it preserves the stage's elapsed time and progress counters, making it useful
// for naming the current item within a long-running stage.
func (t *Tracker) SetStageLabel(name string) {
	t.mu.Lock()
	if t.stage == "" {
		t.mu.Unlock()
		return
	}
	t.stage = name
	// A label change is a meaningful low-cardinality event, so show it even on
	// piped output rather than waiting for the normal progress throttle.
	t.lastPrint = time.Time{}
	t.mu.Unlock()
	t.render(false)
}

// New starts a Tracker writing to w (typically os.Stderr), detecting whether w is
// a terminal to choose the rendering style.
func New(w *os.File) *Tracker {
	t := &Tracker{
		w:      w,
		isTTY:  isTerminal(w),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go t.loop()
	return t
}

// Stage finalizes the previous stage's line and begins a new stage named name.
// total is the number of Advance units expected; pass 0 (or less) for an
// indeterminate stage, which shows a spinner and elapsed time but no percentage.
func (t *Tracker) Stage(name string, total int) {
	t.finishCurrent()
	t.mu.Lock()
	t.stage = name
	now := time.Now()
	t.stageStart = now
	t.spin = 0
	t.lastPct = -1
	t.lastPrint = time.Time{}
	t.mu.Unlock()
	t.current.Store(0)
	t.total.Store(int64(total))
	t.render(false)
}

// AddTotal grows the current stage's expected unit count by n (see Reporter),
// letting a collector that discovers its sub-work only while running report
// finer-grained progress. It does not itself count as progress (the paired
// Advance calls do), so it leaves the stall timer untouched. Safe to call from
// many goroutines concurrently.
func (t *Tracker) AddTotal(n int) {
	if n <= 0 {
		return
	}
	t.total.Add(int64(n))
}

// Advance records that n units of the current stage completed. Safe to call from
// many goroutines concurrently.
func (t *Tracker) Advance(n int) {
	t.current.Add(int64(n))
}

// Log prints msg on its own line without disturbing the progress line: on a TTY
// it clears the current line, writes msg, and lets the next tick redraw the bar.
// Use it for warnings and per-item errors that should survive above the bar.
func (t *Tracker) Log(msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isTTY {
		fmt.Fprintf(t.w, "\r\033[K%s\n", msg)
	} else {
		fmt.Fprintf(t.w, "%s\n", msg)
	}
}

// Stop finalizes the current stage line and shuts down the renderer. Idempotent.
func (t *Tracker) Stop() {
	t.stopOnce.Do(func() {
		t.finishCurrent()
		close(t.stopCh)
		<-t.doneCh
	})
}

func (t *Tracker) loop() {
	defer close(t.doneCh)
	tick := time.NewTicker(renderInterval)
	defer tick.Stop()
	for {
		select {
		case <-t.stopCh:
			return
		case <-tick.C:
			t.render(false)
		}
	}
}

// finishCurrent prints the final form of the active stage line (with a trailing
// newline on a TTY) so the next stage starts cleanly.
func (t *Tracker) finishCurrent() {
	t.mu.Lock()
	has := t.stage != ""
	t.mu.Unlock()
	if has {
		t.render(true)
	}
}

func (t *Tracker) render(final bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stage == "" {
		return
	}
	cur := t.current.Load()
	tot := t.total.Load()
	now := time.Now()

	if t.isTTY {
		if !final {
			t.spin = (t.spin + 1) % len(spinnerFrames)
		}
		// Clamp to one terminal row: a line wider than the terminal wraps, and
		// then the carriage-return redraw only clears the last visual row,
		// stacking a fresh copy of the bar on every tick instead of overwriting.
		line := clampWidth(t.line(cur, tot, now), termWidth(t.w))
		fmt.Fprintf(t.w, "\r\033[K%s", line)
		if final {
			fmt.Fprint(t.w, "\n")
		}
		return
	}

	// Piped/redirected: throttle so logs don't flood, but always print the final
	// line and the first line of a stage.
	pct := pctOf(cur, tot)
	if !final && !(pct-t.lastPct >= nonTTYStepPct || now.Sub(t.lastPrint) >= nonTTYStepGap) {
		return
	}
	t.lastPct = pct
	t.lastPrint = now
	fmt.Fprintf(t.w, "%s\n", t.line(cur, tot, now))
}

// line builds the display string; caller holds t.mu.
func (t *Tracker) line(cur, tot int64, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-12s", t.stage)
	if tot > 0 {
		filled := int(int64(barWidth) * cur / tot)
		if filled > barWidth {
			filled = barWidth
		}
		b.WriteString(" [")
		b.WriteString(strings.Repeat("█", filled))
		b.WriteString(strings.Repeat("░", barWidth-filled))
		fmt.Fprintf(&b, "] %3d%% (%d/%d)", pctOf(cur, tot), cur, tot)
	} else {
		fmt.Fprintf(&b, " (%d done)", cur)
	}
	if t.isTTY {
		fmt.Fprintf(&b, " %c", spinnerFrames[t.spin])
	}
	fmt.Fprintf(&b, " %s", now.Sub(t.stageStart).Truncate(time.Second))
	return b.String()
}

// clampWidth truncates s to at most width display columns so a redrawn line
// stays on one terminal row. It counts runes as one column each — true for
// every glyph the bar uses (ASCII, the █/░ cells, and the braille spinner) — and
// is a no-op when width <= 0 (unknown terminal size).
func clampWidth(s string, width int) string {
	if width <= 0 {
		return s
	}
	n := 0
	for i := range s {
		if n == width {
			return s[:i]
		}
		n++
	}
	return s
}

func pctOf(cur, tot int64) int {
	if tot <= 0 {
		return 0
	}
	p := int(cur * 100 / tot)
	if p > 100 {
		p = 100
	}
	return p
}

// isTerminal reports whether f is a character device (a terminal), which
// distinguishes an interactive run from a redirected pipe or file.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
