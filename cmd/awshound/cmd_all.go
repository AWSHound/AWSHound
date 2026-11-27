package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AWSHound/AWSHound/internal/emit"
	"github.com/AWSHound/AWSHound/internal/metrics"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/runtime"
	"github.com/AWSHound/AWSHound/internal/store"
)

// cmdAll runs the whole pipeline in one invocation, persisting every artifact:
// raw collect JSON (--raw, live collection only), the built graph ZIP (--built),
// and the final OpenGraph ZIP (-o). Data comes from live AWS (--profile), an existing
// raw collect directory (--input-dir), or a single GAAD file (--gaad).
//
// It is the primary command (also the no-subcommand default) and supersedes an
// in-memory-only mode: writing the intermediates costs little, lets a slow or
// failed run resume with `process`/`emit`, and gives e2e/integration tests a
// single command to invoke plus every stage's output to assert against.
//
// A live run interrupted partway (crash, throttling, killed pod) can be resumed
// with `all --resume --raw <dir> <live source>`: the units already written to
// <dir>/<account>/<service>.json are ingested from disk and only the missing ones
// are re-collected (see planResume). --input-dir stays purely offline and may not be
// combined with a live source.
func cmdAll(args []string) {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	var (
		gaadPath, inputDir, s3Filter, awsConfig, awsCreds string
		rawDir, builtOut, out, metricsOut                 string
		errorLog, orgRole                                 string
		collectors, regions, profiles                     stringSlice
		maxConc, accountConc                              int
		maxAPIRequests                                    int64
		maxAPIPerMinute                                   int
		verbose, resume                                   bool
	)
	fs.StringVar(&gaadPath, "gaad", "", "offline: build from a single GAAD JSON file")
	fs.StringVar(&inputDir, "input-dir", "", "offline: build from an existing directory of collect JSON")
	fs.Var(&collectors, "collectors", "comma-separated services to collect (default: all except s3; add s3 explicitly to include it)")
	fs.Var(&profiles, "profile", "AWS CLI profile to collect (repeatable / comma-separated); merged with --aws-config's bloodhound_collect profiles")
	fs.StringVar(&awsConfig, "aws-config", "", "AWS config file; collect every profile whose section sets bloodhound_collect = true")
	fs.StringVar(&awsCreds, "aws-credentials", "", "AWS shared credentials file (default: ~/.aws/credentials)")
	fs.StringVar(&orgRole, "org-role", "", "assume this role (e.g. OrganizationAccountAccessRole) into every account in the AWS Organization and collect them all")
	fs.Var(&regions, "regions", "comma-separated regions (default: us-east-1)")
	fs.StringVar(&s3Filter, "s3-filter", "", "path to S3 filter config; include/exclude buckets and objects (default: process all)")
	fs.StringVar(&rawDir, "raw", "raw", "directory for the raw collect JSON artifact (live collection only)")
	fs.BoolVar(&resume, "resume", false, "resume a live collection from --raw: skip (account,service) units already collected there and fetch only the missing ones (requires a live source)")
	fs.StringVar(&builtOut, "built", "built.zip", "path for the built-graph ZIP archive (default: built.zip next to -o)")
	fs.StringVar(&out, "o", "graph.zip", "output OpenGraph ZIP archive path (.zip appended if omitted)")
	fs.StringVar(&out, "output", "graph.zip", "output OpenGraph ZIP archive path (alias of -o; .zip appended if omitted)")
	fs.StringVar(&metricsOut, "metrics", "", "write run metrics JSON to this path")
	fs.StringVar(&errorLog, "error-log", "", "write per-service collection errors JSON to this path (default: collect-errors.json next to -o; live collection only)")
	fs.IntVar(&maxConc, "max-concurrency", 200, "max concurrent regional/global collector workers (<=0 for unbounded); not a request rate cap")
	fs.IntVar(&accountConc, "account-concurrency", 0, "max accounts processed concurrently (0 = auto: min(NumCPU, 8)); bounds peak memory")
	fs.Int64Var(&maxAPIRequests, "max-api-requests", 0, "hard cap on AWS SDK HTTP send attempts, including retries (0 = unlimited)")
	fs.IntVar(&maxAPIPerMinute, "max-api-requests-per-minute", 0, "hard rolling-minute cap on AWS SDK HTTP send attempts, including retries (0 = unlimited)")
	fs.BoolVar(&verbose, "v", false, "print detailed current-work logging instead of the progress bar")
	fs.BoolVar(&verbose, "verbose", false, "print detailed current-work logging instead of the progress bar (alias of -v)")
	setGroupedUsage(fs,
		"awshound all — collect, build, and emit in one run.\n\n"+
			"usage:\n"+
			"  awshound all [flags]\n"+
			"  (also the default when awshound is run with no subcommand)\n\n"+
			"Provide one source: live AWS (--aws-config / --profile / --org-role),\n"+
			"--input-dir (raw JSON), or --gaad (a single GAAD file).",
		"",
		[]flagGroup{
			{"Source (choose one)", []string{"aws-config", "profile", "org-role", "input-dir", "gaad"}},
			{"Collection (live AWS)", []string{"collectors", "regions", "aws-credentials", "max-concurrency", "account-concurrency", "max-api-requests", "max-api-requests-per-minute", "resume"}},
			{"Filtering", []string{"s3-filter"}},
			{"Output", []string{"o", "raw", "built", "metrics", "error-log"}},
			{"Logging", []string{"v"}},
		})
	_ = fs.Parse(args)
	builtExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "built" {
			builtExplicit = true
		}
	})
	out = runtime.ZIPOutputPath(out, "graph.zip")
	if builtExplicit {
		builtOut = runtime.ZIPOutputPath(builtOut, "built.zip")
	} else {
		builtOut = filepath.Join(filepath.Dir(out), "built.zip")
	}
	if filepath.Clean(out) == filepath.Clean(builtOut) {
		fmt.Fprintln(os.Stderr, "all: --output and --built must name different ZIP archives")
		os.Exit(2)
	}

	names := resolveCollectors(collectors)

	// --input-dir selects a purely offline build; combining it with a live source
	// used to silently win and drop the credentials (issue #16). Reject that combo
	// loudly, and point at --resume for the "keep the partial raw dir, collect the
	// rest" case it is usually mistaken for.
	liveSrc := awsConfig != "" || len(profiles) > 0 || orgRole != ""
	if inputDir != "" && liveSrc {
		fmt.Fprintln(os.Stderr, "all: --input-dir builds offline from raw JSON and cannot be combined with a live source (--aws-config/--profile/--org-role); to resume a live collection from a partial raw directory, use --resume --raw <dir> with the live source")
		os.Exit(2)
	}
	if resume && !liveSrc {
		fmt.Fprintln(os.Stderr, "all: --resume needs a live source (--aws-config/--profile/--org-role); it resumes a live collection from the --raw directory")
		os.Exit(2)
	}
	if resume && (gaadPath != "" || inputDir != "") {
		fmt.Fprintln(os.Stderr, "all: --resume applies to live collection only; drop --gaad/--input-dir (the raw directory to resume from is --raw)")
		os.Exit(2)
	}
	if err := validateAPILimits(maxAPIRequests, maxAPIPerMinute); err != nil {
		fmt.Fprintln(os.Stderr, "all:", err)
		os.Exit(2)
	}

	mode := ""
	var env metrics.Environment
	switch {
	case gaadPath != "":
		mode, env = "gaad", offlineEnv([]string{"iam"})
	case inputDir != "":
		mode, env = "dir", offlineEnv(nil)
	case liveSrc:
		mode, env = "live", liveEnv(names, maxConc)
	default:
		fmt.Fprintln(os.Stderr, "all: one source is required: --aws-config, --profile, or --org-role (live AWS), --input-dir, or --gaad")
		os.Exit(2)
	}
	if mode != "live" && (maxAPIRequests != 0 || maxAPIPerMinute != 0) {
		fmt.Fprintln(os.Stderr, "all: API request limits apply only to a live AWS source")
		os.Exit(2)
	}

	apiMetricsOut := ""
	if mode == "live" {
		apiMetricsOut = metricsOut
	}
	ctx, apiCancel, api := newAPIController(context.Background(), apiMetricsOut, maxAPIRequests, maxAPIPerMinute)
	defer apiCancel(nil)
	reporter, m := makeReporter(verbose, metricsOut, env)
	defer reporter.Stop()

	s3f := loadS3Filter(s3Filter)
	s := store.New()
	var ran []string
	live := false
	switch mode {
	case "gaad":
		acct := ingestGAADFile(s, gaadPath)
		ran = []string{"iam"}
		if verbose {
			reporter.Log(fmt.Sprintf("ingested GAAD for account %s", acct))
		}
	case "dir":
		ran = ingestDir(s, inputDir, reporter, verbose, s3f)
		m.SetCollectors(ran)
	case "live":
		live = true
		targets, err := buildLiveTargets(ctx, profiles, orgRole, awsConfig, awsCreds, regions, names, reporter, api)
		if err != nil {
			if stopForAPILimit(reporter, m, metricsOut, api, len(s.Accounts())) {
				os.Exit(1)
			}
			writePartialMetrics(reporter, m, metricsOut, api, len(s.Accounts()), 0, 0)
			fmt.Fprintln(os.Stderr, "all:", err)
			os.Exit(2)
		}
		// Phase 1 — collect: AWS -> raw/, ingesting each payload into the store from
		// memory as it is written (no read-back). The raw/ artifact is still the
		// exact input `process --input-dir raw/` would consume to reproduce this run.
		errLog := runtime.NewCollectErrorLog()
		boots := bootstrapAccounts(ctx, targets, regions, maxConc, reporter, verbose, m, errLog)
		if stopForAPILimit(reporter, m, metricsOut, api, len(boots)) {
			os.Exit(1)
		}
		// --resume: fold the units already present in rawDir into the store and trim
		// them from each account's collector list, so collectToDir fetches only the
		// missing ones. Bootstrap still runs (it resolves the account ids the on-disk
		// layout is keyed by, and its cost is negligible beside collection).
		var resumed []string
		if resume {
			resumed = planResume(boots, rawDir, s, s3f, reporter, verbose)
		}
		_, ran, err = collectToDir(ctx, boots, rawDir, s, s3f, resolveAccountConc(accountConc), reporter, verbose, m, errLog)
		finishCollectErrors(errLog, defaultErrorLogPath(errorLog, out), reporter)
		if err != nil {
			if stopForAPILimit(reporter, m, metricsOut, api, len(s.Accounts())) {
				os.Exit(1)
			}
			writePartialMetrics(reporter, m, metricsOut, api, len(s.Accounts()), 0, 0)
			fatal(err)
		}
		if len(resumed) > 0 {
			// Report the union: services in the graph came from disk, from this run,
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
	}

	// Phase 2 — process: stream store -> built.zip/built.json without accumulating the
	// volume-scaling node set (§9 of docs/authorization-tensor.md).
	var nodeCount, edgeCount int
	if err := runtime.WriteZIP(builtOut, runtime.BuiltArtifactName, func(w io.Writer) (err error) {
		nodeCount, edgeCount, err = runtime.StreamBuildToBuilt(s, w, reporter, m)
		return err
	}); err != nil {
		writePartialMetrics(reporter, m, metricsOut, api, len(s.Accounts()), nodeCount, edgeCount)
		fatal(err)
	}

	// Phase 3 — emit: stream built.zip/built.json -> graph.zip/graph.json
	// (id-encoding at the terminal step). Byte-identical to emitting from the
	// in-memory graph, but bounded and compressed without a raw disk copy.
	reporter.Stage("Emit", 0)
	if detailer, ok := reporter.(progress.Detailer); ok {
		detailer.Detail("encoding %s as OpenGraph output %s", builtOut, out)
	}
	in, err := runtime.OpenJSONArtifact(builtOut)
	if err != nil {
		writePartialMetrics(reporter, m, metricsOut, api, len(s.Accounts()), nodeCount, edgeCount)
		fatal(err)
	}
	if err := runtime.WriteZIP(out, runtime.GraphArtifactName, func(w io.Writer) error {
		return emit.StreamGraphFromBuilt(in, w)
	}); err != nil {
		in.Close()
		writePartialMetrics(reporter, m, metricsOut, api, len(s.Accounts()), nodeCount, edgeCount)
		fatal(err)
	}
	if err := in.Close(); err != nil {
		writePartialMetrics(reporter, m, metricsOut, api, len(s.Accounts()), nodeCount, edgeCount)
		fatal(err)
	}

	reporter.Stop()
	if metricsOut != "" {
		if err := writeMetrics(reporter, m, metricsOut, api, len(s.Accounts()), nodeCount, edgeCount, true); err != nil {
			fatal(err)
		}
	}

	artifacts := "built: " + builtOut
	if live {
		artifacts = "raw: " + rawDir + "/, " + artifacts
	}
	fmt.Printf("wrote %s (%s): %d nodes, %d edges (%d account(s); collectors: %s)\n",
		out, artifacts, nodeCount, edgeCount, len(s.Accounts()), strings.Join(ran, ","))
}
