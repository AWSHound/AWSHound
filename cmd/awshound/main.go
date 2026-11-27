// Command awshound collects AWS identity/authorization data and builds a
// BloodHound OpenGraph JSON graph. Its work is three phases, exposed both as
// subcommands (for running them independently, with on-disk artifacts between)
// and as a single all-in-one "run":
//
//	collect   AWS            -> raw/          (a directory of raw collect JSON)
//	process   raw/           -> built.json    (the built graph, raw ARN ids)
//	emit      built.json     -> graph.json    (OpenGraph JSON: encoded ids + envelope)
//	run       AWS | raw/ | GAAD -> graph.json (all phases in one process)
//
// Invoked with no subcommand (leading flag), it behaves as "run" for backward
// compatibility.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AWSHound/AWSHound/internal/collect"
	"github.com/AWSHound/AWSHound/internal/ingest"
	"github.com/AWSHound/AWSHound/internal/metrics"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/runtime"
	"github.com/AWSHound/AWSHound/internal/store"
)

// stringSlice is a repeatable / comma-separated flag value (e.g. --profile a,b
// or --profile a --profile b), matching the Python CLI's list flags.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }

func (s *stringSlice) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// accountTarget is one account to bootstrap and collect: a human-readable label
// for logs/metrics, the collector set to run for it, and a factory that builds its
// session for the resolved bootstrap region. The factory indirection lets a single
// Bootstrap/Collect path mix credential sources — a named AWS profile, or an STS
// assume-role into an organization child account — behind one uniform flow.
type accountTarget struct {
	label      string
	collectors []string
	newSession func(ctx context.Context, region string) (*collect.Session, error)
}

func main() {
	// Optional CPU profile for performance work: set GOAWSHOUND_CPUPROFILE=<path>.
	// Flushed on normal exit and on SIGINT/SIGTERM so a killed long run is still
	// analyzable.
	if p := os.Getenv("GOAWSHOUND_CPUPROFILE"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fatal(err)
		}
		defer pprof.StopCPUProfile()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sig
			pprof.StopCPUProfile()
			f.Close()
			os.Exit(130)
		}()
	}

	args := os.Args[1:]
	if len(args) == 0 {
		usage(2)
	}
	switch args[0] {
	case "collect":
		cmdCollect(args[1:])
	case "process":
		cmdProcess(args[1:])
	case "emit":
		cmdEmit(args[1:])
	case "all", "run": // "run" is a deprecated alias for "all"
		cmdAll(args[1:])
	case "help", "-h", "--help":
		usage(0)
	default:
		// No subcommand (leading flag) → behave as "all" for backward compatibility.
		if strings.HasPrefix(args[0], "-") {
			cmdAll(args)
			return
		}
		fmt.Fprintf(os.Stderr, "awshound: unknown command %q\n", args[0])
		usage(2)
	}
}

// usage prints the top-level overview through the same width-aware helpers the
// per-command grouped help uses (setGroupedUsage): the command list is a two-column
// layout wrapped to the terminal width with a hanging indent, and the trailing
// prose wraps too, so the default usage matches every "<command> -h" screen.
func usage(code int) {
	w := os.Stderr
	cols := terminalCols(w)

	writeBlock(w, "awshound — collect AWS data and build a BloodHound OpenGraph.")
	fmt.Fprint(w, "\nusage:\n  awshound <command> [flags]\n\ncommands:\n")

	commands := []struct{ name, desc string }{
		{"collect", "fetch AWS data into a raw JSON directory (AWS -> raw/)"},
		{"process", "build the graph from raw collect JSON (raw/ -> built.json)"},
		{"emit", "encode the built graph as OpenGraph JSON (built.json -> graph.json)"},
		{"all", "run every phase, persisting each artifact (AWS | raw/ | GAAD -> graph.json)"},
	}
	// Align descriptions just past the widest command name (name + a 3-space gap).
	cmdCol := usageIndent + 2
	for _, c := range commands {
		if n := usageIndent + len(c.name) + 3; n > cmdCol {
			cmdCol = n
		}
	}
	for _, c := range commands {
		writeTwoColRow(w, c.name, c.desc, cmdCol, cols)
	}

	// Examples are literal, copy-pasteable command lines, so they are printed
	// verbatim rather than wrapped (wrapping would corrupt the commands).
	fmt.Fprint(w, `
examples:
  awshound all     --profile prod -o graph.json               # collect one profile + build + emit
  awshound all     --org-role OrganizationAccountAccessRole   # collect the whole AWS Organization
  awshound all     --aws-config ~/.aws/config -o graph.json   # collect + build + emit
  awshound collect --aws-config ~/.aws/config -o raw/         # AWS -> raw JSON only
  awshound all     --input-dir raw/ -o graph.json             # build from collected JSON
  awshound process --input-dir raw/ -o built.json             # build only
  awshound emit    -i built.json -o graph.json                # encode only
`)

	writeWrapped(w, `Live collection chooses accounts from --profile (repeatable), the --aws-config file (every profile whose section sets "bloodhound_collect = true"), or --org-role <role> (assume that role across the whole AWS Organization, e.g. OrganizationAccountAccessRole).`, cols)
	writeWrapped(w, `With no command, flags are treated as "all". Run "awshound <command> -h" for a command's full flag list.`, cols)
	os.Exit(code)
}

// makeReporter builds the display reporter (progress bar, or -v verbose logger)
// and, when metricsOut is set, tees it into a RunMetrics accumulator so stage
// timings are recorded off the same Stage() calls. The returned *RunMetrics is
// nil when metrics are off; all its Record* methods are nil-safe.
func makeReporter(verbose bool, metricsOut string, env metrics.Environment) (progress.Reporter, *metrics.RunMetrics) {
	var display progress.Reporter
	if verbose {
		display = progress.NewLogger(os.Stderr)
	} else {
		display = progress.New(os.Stderr)
	}
	if metricsOut == "" {
		return display, nil
	}
	m := metrics.New(env)
	return progress.Multi(display, m), m
}

// liveEnv is the metrics environment for AWS-touching commands (collect, run live).
func liveEnv(collectors []string, maxConc int) metrics.Environment {
	mode, attempts := collect.RetryPolicy()
	return metrics.Environment{
		Collectors:       collectors,
		MaxConcurrency:   maxConc,
		RetryMode:        mode,
		RetryMaxAttempts: attempts,
		NumCPU:           goruntime.NumCPU(),
	}
}

// offlineEnv is the metrics environment for offline commands (process, emit, run
// from a directory/GAAD) — no AWS knobs apply.
func offlineEnv(collectors []string) metrics.Environment {
	return metrics.Environment{Collectors: collectors, NumCPU: goruntime.NumCPU()}
}

// bootedSession is one account, bootstrapped and ready to collect.
type bootedSession struct {
	label      string
	accountID  string
	sess       *collect.Session
	regions    int
	collectors []string
}

// bootstrapAccounts resolves each target's identity (STS) and enabled regions
// (EC2) up front under a "Bootstrap" stage, one goroutine per target, returning
// the sessions that came up. Running this as its own barrier lets callers size
// the Collect stage exactly before any collection starts. A per-target failure
// (bad credentials, denied/failed AssumeRole, region-discovery error) is
// best-effort: that account is recorded in the collection error log and skipped
// so collection continues for the rest. Shared by `collect` and `all`'s live
// path; the targets abstract over the credential source behind one flow.
func bootstrapAccounts(ctx context.Context, targets []accountTarget, regions []string, maxConc int, reporter progress.Reporter, verbose bool, m *metrics.RunMetrics, errLog *runtime.CollectErrorLog) []bootedSession {
	region := "us-east-1"
	if len(regions) > 0 {
		region = regions[0]
	}
	limiter := collect.NewLimiter(maxConc)

	type result struct {
		b     bootedSession
		label string
		err   error
	}
	reporter.Stage("Bootstrap", len(targets))
	out := make([]result, len(targets))
	var wg sync.WaitGroup
	wg.Add(len(targets))
	for i, t := range targets {
		go func(i int, t accountTarget) {
			defer wg.Done()
			defer reporter.Advance(1)
			if detailer, ok := reporter.(progress.Detailer); ok {
				detailer.Detail("bootstrapping %s", t.label)
			}
			start := time.Now()
			sess, err := t.newSession(ctx, region)
			if err != nil {
				out[i] = result{label: t.label, err: fmt.Errorf("%s: %w", t.label, err)}
				return
			}
			sess.SetLimiter(limiter)
			sess.SetProgress(reporter.Advance)
			sess.SetAddTotal(reporter.AddTotal)
			rcount := len(regions)
			if len(regions) > 0 {
				sess.SetRegions(regions)
			} else if rs, derr := sess.DiscoverRegions(ctx); derr != nil {
				out[i] = result{label: t.label, err: fmt.Errorf("%s: %w", t.label, derr)}
				return
			} else {
				rcount = len(rs)
			}
			id, err := sess.AccountID(ctx)
			if err != nil {
				out[i] = result{label: t.label, err: fmt.Errorf("%s: %w", t.label, err)}
				return
			}
			// Per-region timing only when metrics are on (fanRegions skips the
			// timing overhead otherwise); the account id is bound here.
			if m != nil {
				sess.SetRegionMetric(func(service, region string, d time.Duration) {
					m.RecordRegion(id, service, region, d)
				})
			}
			m.RecordBootstrap(id, t.label, rcount, time.Since(start))
			out[i] = result{b: bootedSession{label: t.label, accountID: id, sess: sess, regions: rcount, collectors: t.collectors}}
		}(i, t)
	}
	wg.Wait()

	boots := make([]bootedSession, 0, len(targets))
	for _, r := range out {
		if r.err != nil {
			recordBootstrapError(errLog, r.label, r.err)
			if verbose {
				reporter.Log(fmt.Sprintf("bootstrap: %v — skipping this account", r.err))
			}
			continue
		}
		boots = append(boots, r.b)
	}
	if len(boots) == 0 {
		reporter.Log(fmt.Sprintf("bootstrap: no accounts could be bootstrapped (all %d target(s) failed)", len(targets)))
	} else if verbose {
		for _, b := range boots {
			reporter.Log(fmt.Sprintf("bootstrap: %s -> account %s (%d regions)", b.label, b.accountID, b.regions))
		}
	}
	return boots
}

func recordBootstrapError(errLog *runtime.CollectErrorLog, label string, err error) {
	accountID := ""
	if len(label) == 12 && strings.Trim(label, "0123456789") == "" {
		accountID = label
	}
	errLog.Record(runtime.CollectError{
		AccountID: accountID,
		Profile:   label,
		Service:   "bootstrap",
		Message:   err.Error(),
	})
}

const (
	collectorsFlagUsage = "comma-separated services to collect; replaces the default list (default: all except s3; pass iam,kms,ssm,ec2,lambda,cloudformation,eks,organizations,s3 to include s3)"
	regionsFlagUsage    = "comma-separated regions to collect (default: auto-discover enabled regions)"
)

// resolveCollectors returns the requested collector set, defaulting to
// runtime.DefaultCollectors (all except s3).
func resolveCollectors(collectors stringSlice) []string {
	names := []string(collectors)
	if len(names) == 0 {
		names = runtime.DefaultCollectors
	}
	return names
}

// profilesFromConfig returns the profiles opted in via `bloodhound_collect = true`
// in the given AWS config file. Fatal if the file can't be read.
func profilesFromConfig(awsConfig string) []string {
	profs, err := collect.ProfilesToCollect(awsConfig)
	if err != nil {
		fatal(err)
	}
	return profs
}

// ingestDir recursively ingests a directory of collect JSON into s (the "Ingest"
// stage), fatal on error, and returns the sorted set of services ingested. Shared
// by `process` and `all`.
func ingestDir(s *store.Store, dir string, reporter progress.Reporter, verbose bool, s3Filter *model.S3FilterConfig) []string {
	res, err := ingest.Directory(s, dir, reporter, s3Filter)
	if err != nil {
		reporter.Stop()
		fatal(err)
	}
	if verbose {
		reporter.Log(fmt.Sprintf("ingested %d file(s) from %s (%d skipped, %d account(s))",
			res.Files, dir, res.Skipped, len(s.Accounts())))
	}
	return res.Services()
}

// sortedKeys returns the keys of a set, sorted.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ingestGAADFile ingests a single GAAD JSON file into the store and returns the
// account id it landed under.
func ingestGAADFile(s *store.Store, path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	raw, err = model.NormalizeGAADDocs(raw)
	if err != nil {
		fatal(err)
	}
	var gaad model.AuthDetails
	if err := json.Unmarshal(raw, &gaad); err != nil {
		fatal(err)
	}
	acct := runtime.AccountIDFromGAAD(&gaad)
	if acct == "" {
		acct = "000000000000"
	}
	s.AddAuthDetails(acct, &gaad)
	return acct
}

// loadS3Filter loads the S3 filter config from path, or returns nil when path is
// empty (no filtering — every collected bucket and object is processed). Fatal on a
// malformed config, so a bad filter fails fast rather than silently mis-filtering.
func loadS3Filter(path string) *model.S3FilterConfig {
	if path == "" {
		return nil
	}
	cfg, err := model.LoadS3Filter(path)
	if err != nil {
		fatal(err)
	}
	return cfg
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "awshound:", err)
	os.Exit(1)
}

// defaultErrorLogPath resolves the collection error-log destination: an explicit
// --error-log value wins; otherwise it defaults to collect-errors.json in the same
// directory as the primary output (the -o path, or its parent for a directory
// output), so the error log lands next to the artifacts it explains.
func defaultErrorLogPath(explicit, primaryOutput string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(filepath.Dir(primaryOutput), "collect-errors.json")
}

// finishCollectErrors writes the accumulated service-level collection errors to
// path and prints a red, per-service one-line summary above the progress display.
// It is a no-op when no errors were recorded, so a clean run leaves no file and
// prints nothing. A failure to write the log is surfaced as a warning, not a fatal
// error — a run that collected data should not be lost over a log-write failure.
func finishCollectErrors(errLog *runtime.CollectErrorLog, path string, reporter progress.Reporter) {
	if errLog.Len() == 0 {
		return
	}
	if err := errLog.WriteJSON(path); err != nil {
		reporter.Log(fmt.Sprintf("warning: could not write error log %s: %v", path, err))
		path = ""
	}
	msg := fmt.Sprintf("⚠ %d collection error(s) by service: %s", errLog.Len(), errLog.SummaryByService())
	if path != "" {
		msg += fmt.Sprintf(" (see %s)", path)
	}
	reporter.Log(red(msg))
}

// red wraps s in an ANSI red SGR sequence when stderr is a terminal (where the
// progress display lives), and returns it unchanged otherwise so redirected logs
// stay plain-text.
func red(s string) string {
	fi, err := os.Stderr.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return s
	}
	return "\033[31m" + s + "\033[0m"
}
