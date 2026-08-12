package progress

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// stampFormat is the wall-clock prefix on every verbose log line.
const stampFormat = "15:04:05"

// heartbeatInterval is how often the Logger prints a "still working" line while a
// stage is otherwise quiet, so a long-running or hung stage is still visible.
const heartbeatInterval = 3 * time.Second

// Logger is the verbose, non-interactive Reporter: it writes plain timestamped
// lines instead of redrawing a bar, so -v output is greppable and safe to
// redirect. It logs each stage's start and finish, every current-work detail,
// throttled progress while units advance, and a "still working" heartbeat when a
// stage goes quiet. All methods are safe for concurrent use.
type Logger struct {
	w *os.File

	mu         sync.Mutex
	stage      string
	stageStart time.Time
	total      int64
	current    int64
	lastLog    time.Time
	lastPct    int

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewLogger starts a verbose Logger writing to w (typically os.Stderr).
func NewLogger(w *os.File) *Logger {
	l := &Logger{
		w:      w,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go l.loop()
	return l
}

// Stage finalizes the previous stage and announces a new one.
func (l *Logger) Stage(name string, total int) {
	l.finish()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.stage = name
	l.stageStart = now
	l.lastLog = now
	l.total = int64(total)
	l.current = 0
	l.lastPct = -1
	if total > 0 {
		l.printf("▶ %s (0/%d)", name, total)
	} else {
		l.printf("▶ %s", name)
	}
}

// AddTotal grows the current stage's expected unit count by n (see
// progress.Reporter), for sub-work a collector only discovers while running. It
// is not itself progress, so it does not reset the heartbeat or log a line.
func (l *Logger) AddTotal(n int) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	l.total += int64(n)
	l.mu.Unlock()
}

// Advance records completed units and logs a progress line, throttled to each 10%
// milestone or at most once per second (and always at completion), so verbose
// output shows steady movement without flooding.
func (l *Logger) Advance(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current += int64(n)
	now := time.Now()
	if l.total <= 0 || l.stage == "" {
		return
	}
	pct := pctOf(l.current, l.total)
	if l.current >= l.total || pct-l.lastPct >= 10 || now.Sub(l.lastLog) >= time.Second {
		l.lastPct = pct
		l.lastLog = now
		l.printf("  %s %d/%d (%d%%)", l.stage, l.current, l.total, pct)
	}
}

// Log writes an out-of-band message as its own timestamped line.
func (l *Logger) Log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.printf("%s", msg)
}

// Detail writes a verbose-only description of the operation currently being
// performed. Unlike progress counters, details are not throttled: -v is an
// explicit request for the node, edge, file, collector, etc. being handled.
func (l *Logger) Detail(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastLog = time.Now()
	l.printf("  • "+format, args...)
}

// Stop finalizes the current stage and halts the heartbeat. Idempotent.
func (l *Logger) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
		<-l.doneCh
		l.finish()
	})
}

func (l *Logger) loop() {
	defer close(l.doneCh)
	tick := time.NewTicker(heartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-tick.C:
			l.heartbeat()
		}
	}
}

// heartbeat prints a "still working" line when the active stage has been quiet
// for a while, so the user can see the process is alive during a long stage.
func (l *Logger) heartbeat() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.stage == "" || now.Sub(l.lastLog) < heartbeatInterval {
		return
	}
	l.lastLog = now
	elapsed := now.Sub(l.stageStart).Truncate(time.Second)
	if l.total > 0 {
		l.printf("  … %s working: %d/%d, %s elapsed", l.stage, l.current, l.total, elapsed)
	} else {
		l.printf("  … %s working: %s elapsed", l.stage, elapsed)
	}
}

// finish logs the completion line for the active stage, if any.
func (l *Logger) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stage == "" {
		return
	}
	elapsed := time.Since(l.stageStart).Truncate(time.Millisecond)
	if l.total > 0 {
		l.printf("✔ %s done (%d/%d) in %s", l.stage, l.current, l.total, elapsed)
	} else {
		l.printf("✔ %s done in %s", l.stage, elapsed)
	}
	l.stage = ""
}

// printf writes one timestamped line; the caller holds l.mu.
func (l *Logger) printf(format string, a ...any) {
	fmt.Fprintf(l.w, "[%s] %s\n", time.Now().Format(stampFormat), fmt.Sprintf(format, a...))
}
