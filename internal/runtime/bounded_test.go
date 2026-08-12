package runtime_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AWSHound/AWSHound/internal/runtime"
)

// BoundedParallel runs all tasks but never more than max concurrently, and runs
// every task exactly once. This is the account-level throttle that bounds how
// many accounts' data are resident at once (§9 of docs/authorization-tensor.md).
func TestBoundedParallelConcurrencyCap(t *testing.T) {
	const max, n = 3, 50
	var inFlight, peak int64
	var ran int64
	var mu sync.Mutex

	runtime.BoundedParallel(max, n, func(i int) {
		cur := atomic.AddInt64(&inFlight, 1)
		mu.Lock()
		if cur > peak {
			peak = cur
		}
		mu.Unlock()
		atomic.AddInt64(&ran, 1)
		// spin a little so tasks actually overlap
		for j := 0; j < 1000; j++ {
			_ = j
		}
		atomic.AddInt64(&inFlight, -1)
	})

	if ran != n {
		t.Fatalf("ran %d tasks, want %d", ran, n)
	}
	if peak > max {
		t.Fatalf("peak concurrency %d exceeded cap %d", peak, max)
	}
}

// A non-positive cap means unbounded (still runs every task once).
func TestBoundedParallelUnbounded(t *testing.T) {
	var ran int64
	runtime.BoundedParallel(0, 10, func(int) { atomic.AddInt64(&ran, 1) })
	if ran != 10 {
		t.Fatalf("ran %d, want 10", ran)
	}
}
