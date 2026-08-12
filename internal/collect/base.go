// Package collect fetches raw AWS service data via aws-sdk-go-v2. It is the Go
// port of AWSHound's core/ingestion package: each Collector fetches one service's
// authorization data (IAM, EC2, S3, ...) from a shared Session.
//
// Session replaces boto3's Session together with BaseCollector's _build_session,
// _get_account_id, and _discover_regions helpers (core/ingestion/base.py): it
// wraps a resolved aws.Config and memoizes the caller's account id
// (sts:GetCallerIdentity) and the account's enabled regions (ec2:DescribeRegions),
// which most collectors need before they fan out per region.
//
// Conventions shared by the concrete collectors are stated here once; each
// <Svc>Collector (the port of AWSHound's <Svc>Collector, core/ingestion/<svc>.py)
// documents only its own specifics:
//
//   - Region-scoped services (EC2, KMS, SSM, Lambda, CloudFormation, EKS) fan out
//     over s.DiscoverRegions via fanRegions and, per region, build a client with
//     s.regionCfg(region), stamping each resource with its region. Global services
//     (IAM, S3, Organizations) make a single set of calls with s.regionCfg("").
//   - Best-effort fidelity: per-region and per-resource failures are skipped (the
//     Python's per-region on_error skip and per-call try/except), so a partial
//     permission set still yields a usable graph. Only the account-id and
//     region-discovery calls surface an error from Fetch.
//   - The three collection dimensions run concurrently: accounts (goroutine per
//     profile in runtime.liveCollect), services (goroutine per collector in
//     runtime.Collect), and regions (goroutine per region via fanRegions here) —
//     the goroutine model that replaces AWSHound's ThreadPoolExecutor fan-out.
//     Per-resource enrichment within a region is still walked sequentially; the
//     collected order is unaffected because fanRegions preserves region order.
package collect

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"github.com/AWSHound/AWSHound/internal/apireq"
)

// defaultRegion is the endpoint region used for the STS identity call and the
// EC2 region-discovery call when the session has no region resolved from the
// region argument, the profile, or the environment. It mirrors base.py's
// `session.region_name or "us-east-1"` fallback.
const defaultRegion = "us-east-1"

// maxRetryAttempts is how many times the SDK retries a throttled or transient
// request before giving up. It is deliberately higher than the SDK default (3)
// because the accounts × services × regions fan-out issues many calls at once,
// so throttling (RequestLimitExceeded / ThrottlingException) is expected under
// load; adaptive retry mode (see NewSession) pairs these attempts with a
// client-side rate limiter that eases the send rate when throttling is observed.
const maxRetryAttempts = 10

// RetryPolicy reports the retry configuration NewSession applies to every client,
// so a caller (e.g. the metrics writer) can record it without duplicating the
// constants.
func RetryPolicy() (mode string, maxAttempts int) {
	return "adaptive", maxRetryAttempts
}

// Collector fetches raw data for a single AWS service. It is the Go equivalent of
// AWSHound's abstract BaseCollector: Service replaces the _service_name attribute
// and Fetch replaces the abstract fetch(**creds) method. Credentials and region
// come from the shared Session (built from an AWS profile or the default
// credential chain), so Fetch takes no credential arguments.
type Collector interface {
	// Service returns the service identifier (e.g. "iam", "ec2"), matching
	// BaseCollector.service_name.
	Service() string
	// Fetch collects the service's data using the shared session. The concrete
	// return type is service-specific and the caller type-asserts it, mirroring
	// the Python fetch's Any return.
	Fetch(ctx context.Context, s *Session) (any, error)
}

// Session wraps a resolved aws.Config and memoizes per-account facts that
// collectors need repeatedly. It is safe for concurrent use by multiple collector
// goroutines: the account id and region list are each fetched at most once, and a
// failed fetch is not cached so it can be retried. A Session must not be copied
// after first use (it holds a sync.Mutex); pass the *Session.
type Session struct {
	// Cfg is the resolved AWS config; collectors build per-region service clients
	// from it via s.regionCfg(region).
	Cfg aws.Config
	// Region is the region resolved for this session (from the region argument,
	// the profile, or the environment); may be "" when none was configured.
	Region string

	// limiter caps concurrent in-flight AWS operations; shared by pointer across
	// every Session so one cap spans the whole run. Nil means unbounded.
	limiter *Limiter

	// onProgress, when set, is called with the number of leaf collection units
	// that just completed — one per region worker (fanRegions) and one per global
	// collector — so a caller can drive a progress display. Nil means no reporting.
	// It may be invoked concurrently, so it must be safe for concurrent use.
	onProgress func(int)

	// onAddTotal, when set, grows the progress denominator by the given count for
	// sub-work a global collector only discovers while running (buckets, GAAD
	// pages, org policies) — see addWork. Each added unit is matched by a later
	// tick, so the stage still ends at 100%. Nil disables the finer granularity
	// (the collector then reports only its single completion tick). Invoked
	// concurrently, so it must be safe for concurrent use.
	onAddTotal func(int)

	// onRegion, when set, receives the wall-clock a single region worker spent for
	// a service, so a caller can record per-region timing for troubleshooting. Nil
	// disables the (small) per-region timing. Invoked concurrently, so it must be
	// safe for concurrent use.
	onRegion func(service, region string, d time.Duration)

	mu        sync.Mutex // guards the memoized fields below
	accountID string     // cached sts:GetCallerIdentity Account ("" until fetched)
	regions   []string   // cached ec2:DescribeRegions result (nil until fetched)
}

// NewSession builds a Session from an optional shared-config profile and region,
// resolving credentials through the standard aws-sdk-go-v2 default chain. It is
// the port of BaseCollector._build_session for the profile/region path; explicit
// static keys are supplied through the environment or the profile in this build.
// Passing an API-request controller opts the session and every client derived
// from it into per-service/operation request accounting.
func NewSession(ctx context.Context, profile, region string, controller ...*apireq.Controller) (*Session, error) {
	return NewSessionFromFiles(ctx, profile, region, "", "", controller...)
}

// NewSessionFromFiles is NewSession that can additionally override the shared
// config-file and credentials-file locations (config.WithSharedConfigFiles /
// WithSharedCredentialsFiles) when configFile / credsFile are non-empty, so a
// caller can point at arbitrary AWS config and credentials files rather than the
// defaults (~/.aws/config, ~/.aws/credentials). An empty path leaves that file at
// its default location; credentials still resolve through the normal chain
// (credentials file, SSO, role assumption). The optional controller is installed
// during config loading so its instrumentation also covers AWS calls made by
// credential providers.
func NewSessionFromFiles(ctx context.Context, profile, region, configFile, credsFile string, controller ...*apireq.Controller) (*Session, error) {
	// The API option annotates each logical call with its SDK service/operation;
	// the HTTP wrapper observes each SDK HTTP send attempt, including retries. They
	// must be configured together on the shared config so every region/service
	// client gets the same accounting.
	httpClient := sharedHTTPClient
	var apiOptions []func(*middleware.Stack) error
	if len(controller) != 0 && controller[0] != nil {
		httpClient = controller[0].WrapHTTPClient(httpClient)
		apiOptions = append(apiOptions, controller[0].APIOption)
	}

	// Adaptive retry: retry throttled/transient requests with exponential backoff
	// and jitter, and let the SDK's client-side rate limiter throttle the send rate
	// when it observes throttling responses. This is what keeps the wide fan-out
	// from hammering an API into hard failures. Applies to every client built from
	// this config (regionCfg copies it).
	opts := []func(*config.LoadOptions) error{
		config.WithRetryMode(aws.RetryModeAdaptive),
		config.WithRetryMaxAttempts(maxRetryAttempts),
		// One shared HTTP client (one connection pool + DNS cache) for every
		// service/region client, so the accounts × services × regions fan-out reuses
		// connections and resolves each host once instead of per client. See
		// sharedHTTPClient.
		config.WithHTTPClient(httpClient),
	}
	if len(apiOptions) != 0 {
		opts = append(opts, config.WithAPIOptions(apiOptions))
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if configFile != "" {
		opts = append(opts, config.WithSharedConfigFiles([]string{configFile}))
	}
	if credsFile != "" {
		opts = append(opts, config.WithSharedCredentialsFiles([]string{credsFile}))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("collect: load AWS config (profile=%q region=%q config=%q creds=%q): %w", profile, region, configFile, credsFile, err)
	}
	return &Session{Cfg: cfg, Region: cfg.Region}, nil
}

// regionCfg returns a copy of the session config pinned to region. A non-empty
// region overrides the config's region; an empty region keeps the config's own
// region, falling back to defaultRegion only when none was resolved — so global
// callers (STS, IAM, S3, Organizations) still reach a valid endpoint. This is the
// one place client construction picks a region, replacing the per-call
// func(o *X.Options) closures the collectors used to repeat.
func (s *Session) regionCfg(region string) aws.Config {
	cfg := s.Cfg
	switch {
	case region != "":
		cfg.Region = region
	case cfg.Region == "":
		cfg.Region = defaultRegion
	}
	return cfg
}

// AccountID returns the 12-digit AWS account id for the session's credentials via
// sts:GetCallerIdentity, memoizing the result. It is the port of
// BaseCollector._get_account_id.
func (s *Session) AccountID(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accountID != "" {
		return s.accountID, nil
	}
	client := sts.NewFromConfig(s.regionCfg(""))
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("collect: sts GetCallerIdentity: %w", err)
	}
	if out.Account == nil {
		return "", fmt.Errorf("collect: sts GetCallerIdentity returned no account id")
	}
	s.accountID = aws.ToString(out.Account)
	return s.accountID, nil
}

// DiscoverRegions returns the account's enabled regions via ec2:DescribeRegions,
// filtered to opt-in-not-required and opted-in statuses, memoizing the result. It
// is the port of BaseCollector._discover_regions' discovery path; the explicit
// `--regions` override that short-circuited that method in Python is now a caller
// concern (a caller with an explicit region list simply skips this call).
func (s *Session) DiscoverRegions(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regions != nil {
		return s.regions, nil
	}
	client := ec2.NewFromConfig(s.regionCfg(""))
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("opt-in-status"),
			Values: []string{"opt-in-not-required", "opted-in"},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("collect: ec2 DescribeRegions: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, aws.ToString(r.RegionName))
		}
	}
	s.regions = regions
	return s.regions, nil
}

// fanRegions runs fn once per discovered region, concurrently, and returns the
// per-region results in region order (result i corresponds to regions[i]). It is
// the region-level fan-out that replaces the collectors' former sequential
// `for _, region := range regions` loop, so a collector now fetches every region
// at once instead of one after another.
//
// Each goroutine writes only its own result slot, so no locking is needed here;
// fn is expected to be best-effort — swallowing per-region errors and returning a
// partial (possibly empty) result exactly as the sequential loop bodies did — so
// a disabled or denied region contributes nothing without failing the fan-out.
// Only the region-discovery call itself surfaces an error.
func fanRegions[T any](ctx context.Context, s *Session, service string, fn func(ctx context.Context, region string) T) ([]T, error) {
	regions, err := s.DiscoverRegions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]T, len(regions))
	var wg sync.WaitGroup
	wg.Add(len(regions))
	for i, region := range regions {
		go func(i int, region string) {
			defer wg.Done()
			// Bound total concurrent region work across the whole run. On ctx
			// cancellation acquire fails and this region is skipped (zero result),
			// consistent with the best-effort per-region contract.
			if err := s.limiter.acquire(ctx); err != nil {
				return
			}
			defer s.limiter.release()
			if s.onRegion != nil {
				start := time.Now()
				out[i] = fn(ctx, region)
				s.onRegion(service, region, time.Since(start))
			} else {
				out[i] = fn(ctx, region)
			}
			s.tick()
		}(i, region)
	}
	wg.Wait()
	return out, nil
}

// SetRegions pins an explicit region list, short-circuiting DiscoverRegions so
// collectors honor a --regions override instead of enumerating every enabled
// region. This is the caller-side explicit-override path referenced above.
func (s *Session) SetRegions(regions []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.regions = regions
}

// SetLimiter installs the shared concurrency limiter that bounds this session's
// in-flight AWS work. Callers build one Limiter and set the same pointer on every
// session so the cap spans all accounts; a nil limiter leaves the session
// unbounded. Set before the session is handed to Collect.
func (s *Session) SetLimiter(l *Limiter) {
	s.limiter = l
}

// SetProgress installs a callback invoked with the number of completed leaf
// collection units (one per region worker, one per global collector) as work
// finishes, for driving a progress display. Set before the session is handed to
// Collect; the callback must be safe for concurrent use. Nil disables reporting.
func (s *Session) SetProgress(fn func(int)) {
	s.onProgress = fn
}

// SetAddTotal installs a callback that grows the progress denominator as a global
// collector discovers its sub-work (see the onAddTotal field and addWork). Set
// before the session is handed to Collect; the callback must be safe for
// concurrent use. Nil disables the finer-grained tail progress.
func (s *Session) SetAddTotal(fn func(int)) {
	s.onAddTotal = fn
}

// SetRegionMetric installs a callback that receives per-region wall-clock timing
// (service, region, duration) as each region worker finishes, for run metrics.
// Set before the session is handed to Collect; the callback must be safe for
// concurrent use. Nil disables per-region timing.
func (s *Session) SetRegionMetric(fn func(service, region string, d time.Duration)) {
	s.onRegion = fn
}

// tick reports that one leaf collection unit finished. It is a no-op when no
// progress callback is installed.
func (s *Session) tick() {
	if s.onProgress != nil {
		s.onProgress(1)
	}
}

// addWork grows the progress denominator by n for sub-work a global collector has
// just discovered, so it can then tick() once per sub-item and make the tail of a
// long single-unit collector visibly advance instead of appearing hung. Every
// added unit MUST be matched by a later tick() (see the global collectors) so the
// Collect stage still finishes at 100%. A no-op when no callback is installed or
// n<=0.
func (s *Session) addWork(n int) {
	if s.onAddTotal != nil && n > 0 {
		s.onAddTotal(n)
	}
}

// formatTime renders an AWS timestamp as an RFC3339 UTC string (or "" when
// absent), the shared stand-in for the Python collectors' str(datetime) that every
// service's time fields use. The exact text differs from boto3's datetime repr, but
// both are the same UTC instant and downstream consumers treat these as opaque
// metadata strings.
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
