package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/AWSHound/AWSHound/internal/metrics"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/runtime"
	"github.com/AWSHound/AWSHound/internal/store"
)

// cmdCollect fetches AWS data and writes it as raw collect JSON into an output
// directory, one file per account/service: <dir>/<account>/<service>.json. That
// tree is exactly what `process` (and `run --input-dir`) reads back. It does not
// build a graph.
func cmdCollect(args []string) {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	var (
		out, metricsOut, awsConfig, awsCreds string
		errorLog, orgRole                    string
		collectors, regions, profiles        stringSlice
		maxConc, accountConc                 int
		maxAPIRequests                       int64
		maxAPIPerMinute                      int
		verbose, resume                      bool
	)
	fs.Var(&collectors, "collectors", "comma-separated services to collect (default: all except s3; add s3 explicitly to include it)")
	fs.Var(&profiles, "profile", "AWS CLI profile to collect (repeatable / comma-separated); merged with --aws-config's bloodhound_collect profiles")
	fs.StringVar(&awsConfig, "aws-config", "", "AWS config file; collect every profile whose section sets bloodhound_collect = true")
	fs.StringVar(&awsCreds, "aws-credentials", "", "AWS shared credentials file (default: ~/.aws/credentials)")
	fs.StringVar(&orgRole, "org-role", "", "assume this role (e.g. OrganizationAccountAccessRole) into every account in the AWS Organization and collect them all")
	fs.Var(&regions, "regions", "comma-separated regions (default: us-east-1)")
	fs.StringVar(&out, "o", "raw", "output directory for raw collect JSON")
	fs.StringVar(&out, "output", "raw", "output directory (alias of -o)")
	fs.StringVar(&metricsOut, "metrics", "", "write run metrics JSON to this path")
	fs.StringVar(&errorLog, "error-log", "", "write per-service collection errors JSON to this path (default: collect-errors.json next to -o)")
	fs.IntVar(&maxConc, "max-concurrency", 200, "max concurrent regional/global collector workers (<=0 for unbounded); not a request rate cap")
	fs.IntVar(&accountConc, "account-concurrency", 0, "max accounts processed concurrently (0 = auto: min(NumCPU, 8)); bounds peak memory")
	fs.Int64Var(&maxAPIRequests, "max-api-requests", 0, "hard cap on AWS SDK HTTP send attempts, including retries (0 = unlimited)")
	fs.IntVar(&maxAPIPerMinute, "max-api-requests-per-minute", 0, "hard rolling-minute cap on AWS SDK HTTP send attempts, including retries (0 = unlimited)")
	fs.BoolVar(&resume, "resume", false, "resume into an existing -o directory: skip (account,service) units already collected there and fetch only the missing ones")
	fs.BoolVar(&verbose, "v", false, "print detailed current-work logging instead of the progress bar")
	fs.BoolVar(&verbose, "verbose", false, "print detailed current-work logging instead of the progress bar (alias of -v)")
	setGroupedUsage(fs,
		"awshound collect — fetch AWS data into a directory of raw JSON.\n\n"+
			"usage:\n"+
			"  awshound collect --aws-config <file> [flags]\n"+
			"  awshound collect --profile <name> [flags]\n"+
			"  awshound collect --org-role <role> [flags]",
		"",
		[]flagGroup{
			{"Source (at least one)", []string{"aws-config", "profile", "org-role"}},
			{"Collection", []string{"collectors", "regions", "aws-credentials", "max-concurrency", "account-concurrency", "max-api-requests", "max-api-requests-per-minute", "resume"}},
			{"Output", []string{"o", "metrics", "error-log"}},
			{"Logging", []string{"v"}},
		})
	_ = fs.Parse(args)

	if awsConfig == "" && len(profiles) == 0 && orgRole == "" {
		fmt.Fprintln(os.Stderr, "collect: one of --aws-config, --profile, or --org-role is required")
		os.Exit(2)
	}
	if err := validateAPILimits(maxAPIRequests, maxAPIPerMinute); err != nil {
		fmt.Fprintln(os.Stderr, "collect:", err)
		os.Exit(2)
	}

	ctx, apiCancel, api := newAPIController(context.Background(), metricsOut, maxAPIRequests, maxAPIPerMinute)
	defer apiCancel(nil)
	names := resolveCollectors(collectors)
	reporter, m := makeReporter(verbose, metricsOut, liveEnv(names, maxConc))
	defer reporter.Stop()

	targets, err := buildLiveTargets(ctx, profiles, orgRole, awsConfig, awsCreds, regions, names, reporter, api)
	if err != nil {
		if stopForAPILimit(reporter, m, metricsOut, api, 0) {
			os.Exit(1)
		}
		writePartialMetrics(reporter, m, metricsOut, api, 0, 0, 0)
		fmt.Fprintln(os.Stderr, "collect:", err)
		os.Exit(2)
	}

	errLog := runtime.NewCollectErrorLog()
	boots := bootstrapAccounts(ctx, targets, regions, maxConc, reporter, verbose, m, errLog)
	if stopForAPILimit(reporter, m, metricsOut, api, len(boots)) {
		os.Exit(1)
	}
	// --resume: skip the (account,service) units already present under out and fetch
	// only the missing ones. No store is built here (collect only writes raw JSON),
	// so the on-disk files are simply left in place as this run's output.
	var resumed []string
	if resume {
		resumed = planResume(boots, out, nil, nil, reporter, verbose)
	}
	files, ran, collectErr := collectToDir(ctx, boots, out, nil, nil, resolveAccountConc(accountConc), reporter, verbose, m, errLog)
	finishCollectErrors(errLog, defaultErrorLogPath(errorLog, out), reporter)
	if collectErr != nil {
		if stopForAPILimit(reporter, m, metricsOut, api, len(boots)) {
			os.Exit(1)
		}
		writePartialMetrics(reporter, m, metricsOut, api, len(boots), 0, 0)
		fatal(collectErr)
	}
	if len(resumed) > 0 {
		// Report the union: the out/ tree now holds units from disk, from this run,
		// or both.
		set := map[string]bool{}
		for _, svc := range ran {
			set[svc] = true
		}
		for _, svc := range resumed {
			set[svc] = true
		}
		ran = sortedKeys(set)
	}

	reporter.Stop()
	if metricsOut != "" {
		if err := writeMetrics(reporter, m, metricsOut, api, len(boots), 0, 0, true); err != nil {
			fatal(err)
		}
	}

	fmt.Printf("collected %d file(s) into %s/ (%d account(s); collectors: %s)\n",
		files, out, len(boots), strings.Join(ran, ","))
}

// collectToDir runs the Collect stage over bootstrapped sessions, fetching each
// account's services concurrently and writing every raw payload to
// out/<account>/<service>.json. When st is non-nil, each payload is also ingested
// into st from memory as it is written, so a caller (the `all` command) gets a
// populated store without reading the raw directory back from disk. It returns the
// number of files written and the sorted set of services collected. A fetch,
// write, or ingest failure is fatal. Shared by the `collect` and `all` subcommands.
func collectToDir(ctx context.Context, boots []bootedSession, out string, st *store.Store, s3Filter *model.S3FilterConfig, accountConc int, reporter progress.Reporter, verbose bool, m *metrics.RunMetrics, errLog *runtime.CollectErrorLog) (int, []string, error) {
	total := 0
	for _, b := range boots {
		total += runtime.CollectUnits(b.collectors, b.regions)
	}
	m.SetCollectUnits(total)
	reporter.Stage("Collect", total)

	// Each account fetches concurrently; a completed service's raw payload is
	// written under out/<account>/. File writes go to distinct paths, so they are
	// safe to run from the per-account goroutines.
	type acctResult struct {
		ran []string
		err error
	}
	results := make([]acctResult, len(boots))
	// Accounts are throttled to accountConc in flight so peak memory scales with
	// the worker count, not the account count (§9 of docs/authorization-tensor.md).
	runtime.BoundedParallel(accountConc, len(boots), func(i int) {
		{
			b := boots[i]
			if err := context.Cause(ctx); err != nil {
				results[i].err = err
				return
			}
			fetched, err := runtime.FetchAllWithProgress(ctx, b.sess, b.collectors, func(service string) {
				if detailer, ok := reporter.(progress.Detailer); ok {
					detailer.Detail("collecting %s for account %s (%s)", service, b.accountID, b.label)
				}
			})
			if err != nil {
				results[i].err = fmt.Errorf("%s: %w", b.label, err)
				return
			}
			// A run-wide API budget cancellation can surface inside best-effort
			// collectors as an empty-but-successful payload. Never persist those
			// active account units as complete: resume treats a valid raw file as an
			// authoritative completion marker.
			if err := context.Cause(ctx); err != nil {
				results[i].err = err
				return
			}
			dir := filepath.Join(out, b.accountID)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				results[i].err = err
				return
			}
			var ran []string
			for _, fr := range fetched {
				m.RecordService(b.accountID, fr.Service, fr.Duration, fr.Err)
				if fr.Err != nil {
					// Record every failure to the error log (written as JSON and
					// summarized in red at the end). Only echo each one inline under
					// -v; otherwise the per-error lines flood the display and the
					// aggregated summary is the intended surface.
					errLog.Record(runtime.CollectError{
						AccountID: b.accountID,
						Profile:   b.label,
						Service:   fr.Service,
						Message:   fr.Err.Error(),
					})
					if verbose {
						reporter.Log(fmt.Sprintf("collector %s (%s): %v", fr.Service, b.label, fr.Err))
					}
					continue
				}
				if err := writeRawFile(filepath.Join(dir, fr.Service+".json"), fr.Data); err != nil {
					results[i].err = fmt.Errorf("write %s/%s: %w", b.accountID, fr.Service, err)
					return
				}
				// Keep the data in memory too, when a store was supplied, instead of
				// re-reading the file we just wrote. Safe concurrently: the store
				// serializes per-account writes and ARN interning.
				if st != nil {
					if err := runtime.IngestDataFiltered(st, b.accountID, fr.Service, fr.Data, s3Filter); err != nil {
						results[i].err = fmt.Errorf("ingest %s/%s: %w", b.accountID, fr.Service, err)
						return
					}
				}
				if verbose {
					reporter.Log(fmt.Sprintf("collect: %s/%s.json ok (%s)", b.accountID, fr.Service, fr.Duration.Truncate(time.Millisecond)))
				}
				ran = append(ran, fr.Service)
			}
			results[i].ran = ran
		}
	})

	ranSet := map[string]bool{}
	files := 0
	for _, r := range results {
		if r.err != nil {
			return 0, nil, r.err
		}
		for _, svc := range r.ran {
			ranSet[svc] = true
			files++
		}
	}
	return files, sortedKeys(ranSet), nil
}

// resolveAccountConc maps the --account-concurrency flag to a concrete cap: an
// explicit positive value is used as-is; 0 (or negative) auto-selects
// min(NumCPU, 8), mirroring AWSHound's _DEFAULT_MAX_WORKERS.
func resolveAccountConc(n int) int {
	if n > 0 {
		return n
	}
	c := goruntime.NumCPU()
	if c > 8 {
		c = 8
	}
	if c < 1 {
		c = 1
	}
	return c
}

// writeRawFile marshals a collector's raw payload to path. Compact JSON keeps big
// GAAD payloads small; the process/ingest step reads it back regardless of layout.
//
// The write is atomic — a temp file in the destination directory is written, synced
// closed, and renamed into place — so a kill mid-write can never leave a truncated
// <service>.json behind. That guarantee is what makes "the file exists and parses"
// a trustworthy "this unit completed" signal for `all --resume` (issue #16).
func writeRawFile(path string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// CreateTemp makes the file 0o600; match the 0o644 the plain write used.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
