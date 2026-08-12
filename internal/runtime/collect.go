package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/AWSHound/AWSHound/internal/collect"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// regionScopedCollectors is the set of services that fan out per region (they use
// collect.fanRegions in their Fetch); every other collector makes a single set of
// global calls. Kept in sync with the collectors that call fanRegions — it exists
// only so CollectUnits can size the progress denominator correctly.
var regionScopedCollectors = map[string]bool{
	"ec2": true, "kms": true, "ssm": true, "lambda": true, "cloudformation": true, "eks": true,
}

// CollectUnits returns the number of leaf collection units a single account will
// produce for the selected services given its discovered region count: each
// region-scoped service contributes one unit per region (one fanRegions worker),
// and each global service contributes one. Callers sum it across accounts to seed
// the Collect stage's progress total once bootstrap has resolved each account's
// regions.
//
// It is the initial denominator, not the final one: the global collectors (iam,
// s3, organizations) grow the total at runtime via Session.addWork as they
// discover their sub-work (pages/buckets/policies) and emit one matching tick per
// sub-item, so a long single-unit global collector advances visibly instead of
// appearing hung on its lone completion tick. Each added unit is matched by a
// later tick, so the stage still finishes at 100%.
func CollectUnits(names []string, regions int) int {
	n := 0
	for _, name := range names {
		if regionScopedCollectors[name] {
			n += regions
		} else {
			n++
		}
	}
	return n
}

// serviceDef binds a collector to the store-ingest that consumes its Fetch
// result. The ingest wrapper owns the type assertion so Collect can stay generic.
type serviceDef struct {
	Name      string
	Collector collect.Collector
	Ingest    func(*store.Store, string, any) error
}

// DefaultCollectors is the set collected when no --collectors is given, in a
// stable order. s3 is deliberately excluded: its per-bucket control-plane +
// object-listing walk runs serially per account and dominates run time on
// bucket-heavy accounts (see internal/collect/s3.go), so it is opt-in via
// `--collectors ...,s3` rather than part of the default sweep. Every collector in
// allServices remains selectable by name.
var DefaultCollectors = []string{
	"iam", "kms", "ssm", "ec2", "lambda", "cloudformation", "eks", "organizations",
}

func allServices() []serviceDef {
	return []serviceDef{
		{"iam", collect.IAMCollector{}, ingestAs(func(s *store.Store, a string, d *model.AuthDetails) { s.AddAuthDetails(a, d) })},
		{"organizations", collect.OrganizationsCollector{}, ingestAs(store.IngestOrganizations)},
		{"s3", collect.S3Collector{}, ingestAs(store.IngestS3)},
		{"kms", collect.KMSCollector{}, ingestAs(store.IngestKMS)},
		{"ssm", collect.SSMCollector{}, ingestAs(store.IngestSSM)},
		{"ec2", collect.EC2Collector{}, ingestAs(store.IngestEC2)},
		{"lambda", collect.LambdaCollector{}, ingestAs(store.IngestLambda)},
		{"cloudformation", collect.CloudFormationCollector{}, ingestAs(store.IngestCloudFormation)},
		{"eks", collect.EKSCollector{}, ingestAs(store.IngestEKS)},
	}
}

// ingestAs adapts a typed ingest function to the generic serviceDef.Ingest,
// performing the type assertion from the collector's any result.
func ingestAs[T any](fn func(*store.Store, string, *T)) func(*store.Store, string, any) error {
	return func(s *store.Store, acct string, d any) error {
		v, ok := d.(*T)
		if !ok || v == nil {
			return fmt.Errorf("unexpected fetch result type %T", d)
		}
		fn(s, acct, v)
		return nil
	}
}

// IngestData ingests a single raw fetch payload (as returned by FetchAll's
// FetchResult.Data) into the store under accountID, dispatching by service name to
// the same typed ingest the live collect path uses. It lets a caller keep
// collected data in memory while also persisting the raw JSON, avoiding a
// read-back from disk. Returns an error for an unknown service or a payload whose
// type doesn't match the service.
func IngestData(s *store.Store, accountID, service string, data any) error {
	for _, def := range allServices() {
		if def.Name == service {
			return def.Ingest(s, accountID, data)
		}
	}
	return fmt.Errorf("unknown collector %q", service)
}

func selectServices(names []string) ([]serviceDef, error) {
	byName := make(map[string]serviceDef)
	for _, def := range allServices() {
		byName[def.Name] = def
	}
	var out []serviceDef
	for _, n := range names {
		def, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("unknown collector %q", n)
		}
		out = append(out, def)
	}
	return out, nil
}

// CollectResult reports one service's collection outcome and how long its
// Fetch+Ingest took (for run metrics).
type CollectResult struct {
	Service  string
	Err      error
	Duration time.Duration
}

// FetchResult is one service's raw fetched payload, for offline raw output. Data
// is the concrete *model.<Svc>Data (or *model.AuthDetails for iam) the collector
// returned, ready to json.Marshal to a file the `collect` subcommand writes and
// the `process`/ingest path later reads back.
type FetchResult struct {
	Service  string
	Data     any
	Err      error
	Duration time.Duration
}

// FetchAll runs the named collectors concurrently against one session and returns
// each service's raw fetched data without ingesting it. It mirrors Collect's
// fan-out, shared limiter, and best-effort semantics (a failing collector is
// reported in its FetchResult), but stops at Fetch so the caller can serialize the
// raw payloads — the `collect` subcommand's path. Per-unit progress still flows
// through the session's progress callback, so the Collect stage advances the same
// way as a live-into-store run.
func FetchAll(ctx context.Context, sess *collect.Session, names []string) ([]FetchResult, error) {
	return FetchAllWithProgress(ctx, sess, names, nil)
}

// FetchAllWithProgress is FetchAll with an optional callback that fires as each
// service collector starts. It lets verbose callers identify current work while
// normal callers retain FetchAll's quiet behavior.
func FetchAllWithProgress(ctx context.Context, sess *collect.Session, names []string, onStart func(service string)) ([]FetchResult, error) {
	defs, err := selectServices(names)
	if err != nil {
		return nil, err
	}
	results := make([]FetchResult, len(defs))
	var wg sync.WaitGroup
	for i := range defs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			def := defs[i]
			if onStart != nil {
				onStart(def.Name)
			}
			start := time.Now()
			data, err := def.Collector.Fetch(ctx, sess)
			results[i] = FetchResult{Service: def.Name, Data: data, Err: err, Duration: time.Since(start)}
		}(i)
	}
	wg.Wait()
	return results, nil
}

// Collect runs the named collectors against one session concurrently (one
// goroutine per service — the goroutine model that replaces AWSHound's
// ThreadPoolExecutor fan-out), ingesting each into the shared thread-safe store.
// Best-effort: a failing collector is reported in its CollectResult rather than
// aborting the batch, mirroring the Python; the caller decides how to surface it
// (awshound routes it through the progress display). Per-unit progress is
// reported through the session's progress callback (see Session.SetProgress).
func Collect(ctx context.Context, s *store.Store, sess *collect.Session, names []string) ([]CollectResult, error) {
	accountID, err := sess.AccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve account id: %w", err)
	}
	defs, err := selectServices(names)
	if err != nil {
		return nil, err
	}

	results := make([]CollectResult, len(defs))
	var wg sync.WaitGroup
	for i := range defs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			def := defs[i]
			start := time.Now()
			data, err := def.Collector.Fetch(ctx, sess)
			if err != nil {
				results[i] = CollectResult{def.Name, fmt.Errorf("fetch: %w", err), time.Since(start)}
				return
			}
			if err := def.Ingest(s, accountID, data); err != nil {
				results[i] = CollectResult{def.Name, fmt.Errorf("ingest: %w", err), time.Since(start)}
				return
			}
			results[i] = CollectResult{def.Name, nil, time.Since(start)}
		}(i)
	}
	wg.Wait()
	return results, nil
}
