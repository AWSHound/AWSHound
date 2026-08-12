package collect

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFanRegionsRespectsLimiter verifies the shared limiter caps how many region
// workers run at once and that fanRegions still returns one result per region in
// region order. SetRegions preseeds the region list so DiscoverRegions serves it
// from cache and no AWS call is made.
func TestFanRegionsRespectsLimiter(t *testing.T) {
	const (
		numRegions = 40
		cap        = 5
	)
	regions := make([]string, numRegions)
	for i := range regions {
		regions[i] = "region-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}

	s := &Session{}
	s.SetRegions(regions)
	s.SetLimiter(NewLimiter(cap))

	var inFlight, maxInFlight int64
	out, err := fanRegions(context.Background(), s, "test", func(ctx context.Context, region string) string {
		cur := atomic.AddInt64(&inFlight, 1)
		for {
			old := atomic.LoadInt64(&maxInFlight)
			if cur <= old || atomic.CompareAndSwapInt64(&maxInFlight, old, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		return region
	})
	if err != nil {
		t.Fatalf("fanRegions: %v", err)
	}

	if got := int(maxInFlight); got > cap {
		t.Errorf("peak concurrency %d exceeded cap %d", got, cap)
	}
	if len(out) != numRegions {
		t.Fatalf("got %d results, want %d", len(out), numRegions)
	}
	for i, region := range regions {
		if out[i] != region {
			t.Errorf("result[%d] = %q, want %q (order not preserved)", i, out[i], region)
		}
	}
}

// TestFanRegionsUnbounded confirms a nil/zero-cap limiter imposes no bound: with
// no limiter set, every region worker can run concurrently.
// TestFanRegionsReportsRegionMetric verifies the per-region timing callback fires
// once per region with the service name and region, so run metrics can attribute
// time correctly.
func TestFanRegionsReportsRegionMetric(t *testing.T) {
	regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
	s := &Session{}
	s.SetRegions(regions)

	var mu sync.Mutex
	seen := map[string]string{} // region -> service
	s.SetRegionMetric(func(service, region string, d time.Duration) {
		mu.Lock()
		seen[region] = service
		mu.Unlock()
	})

	_, err := fanRegions(context.Background(), s, "ec2", func(ctx context.Context, region string) int {
		return 0
	})
	if err != nil {
		t.Fatalf("fanRegions: %v", err)
	}
	if len(seen) != len(regions) {
		t.Fatalf("got %d region metrics, want %d: %v", len(seen), len(regions), seen)
	}
	for _, r := range regions {
		if seen[r] != "ec2" {
			t.Errorf("region %q reported service %q, want \"ec2\"", r, seen[r])
		}
	}
}

func TestFanRegionsUnbounded(t *testing.T) {
	const numRegions = 12
	regions := make([]string, numRegions)
	for i := range regions {
		regions[i] = "r" + string(rune('a'+i))
	}

	s := &Session{}
	s.SetRegions(regions)
	// No SetLimiter — s.limiter is nil, so acquire/release are no-ops.

	release := make(chan struct{})
	var peak int64
	done := make(chan []string, 1)
	go func() {
		out, _ := fanRegions(context.Background(), s, "test", func(ctx context.Context, region string) string {
			atomic.AddInt64(&peak, 1)
			<-release // block until every worker has started
			return region
		})
		done <- out
	}()

	// Wait for all workers to be simultaneously in flight, proving no cap applied.
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt64(&peak) < numRegions {
		select {
		case <-deadline:
			t.Fatalf("only %d/%d workers started concurrently; unexpected bound", atomic.LoadInt64(&peak), numRegions)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	if out := <-done; len(out) != numRegions {
		t.Fatalf("got %d results, want %d", len(out), numRegions)
	}
}
