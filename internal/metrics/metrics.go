// Package metrics accumulates timing and count data for a awshound run and
// writes it as metrics.json. It replaces the old AWSHound-compatibility shim with
// a run report aimed at troubleshooting a slow collect: how long each pipeline
// stage took, and — within collection — which account, service, and region were
// the slow ones.
//
// A RunMetrics implements progress.Reporter, so it times each stage off the same
// Stage() calls that drive the on-screen display (wired together with
// progress.Multi). Finer detail arrives through the Record* methods, which the
// pipeline calls directly. Every method is safe for concurrent use and nil-safe,
// so callers can pass a nil *RunMetrics when --metrics was not requested and skip
// all the branching.
package metrics

import (
	"sync"
	"time"

	"github.com/AWSHound/AWSHound/internal/apireq"
	"github.com/AWSHound/AWSHound/internal/progress"
)

// *RunMetrics implements progress.Reporter so it can be tee'd alongside the
// on-screen display and time stages off the same Stage() calls.
var _ progress.Reporter = (*RunMetrics)(nil)

// Environment records the run's configuration — the knobs that affect how long a
// collect takes and how hard it hits the AWS APIs.
type Environment struct {
	Collectors       []string `json:"collectors"`
	MaxConcurrency   int      `json:"maxConcurrency"` // 0 means unbounded
	RetryMode        string   `json:"retryMode"`
	RetryMaxAttempts int      `json:"retryMaxAttempts"`
	NumCPU           int      `json:"numCPU"`
}

// RunMetrics accumulates a run's timings and counts.
type RunMetrics struct {
	started time.Time
	env     Environment

	mu            sync.Mutex
	curStage      string
	stageStart    time.Time
	stages        []stageTiming
	edgeFamilies  []stageTiming // per-edge-family build durations, in run order
	accounts      map[string]*accountMetric
	acctOrder     []string
	collectUnits  int
	accountsCount int
	nodes         int
	edges         int
	apiReport     *apireq.Report
	stopOnce      sync.Once
}

type stageTiming struct {
	Name   string `json:"name"`
	Millis int64  `json:"millis"`
}

type accountMetric struct {
	Profile         string
	AccountID       string
	Regions         int
	BootstrapMillis int64
	services        map[string]*serviceMetric
	svcOrder        []string
}

type serviceMetric struct {
	Millis              int64
	Err                 string
	RegionCount         int
	SlowestRegion       string
	SlowestRegionMillis int64
}

// New starts a RunMetrics for the given environment, stamping the run start.
func New(env Environment) *RunMetrics {
	return &RunMetrics{
		started:  time.Now(),
		env:      env,
		accounts: map[string]*accountMetric{},
	}
}

// --- progress.Reporter: stage timing -------------------------------------

// Stage finalizes the previous stage's duration and starts timing name.
func (m *RunMetrics) Stage(name string, total int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeStageLocked()
	m.curStage = name
	m.stageStart = time.Now()
}

// AddTotal is unused for metrics (counts come from the Record* methods).
func (m *RunMetrics) AddTotal(int) {}

// Advance is unused for metrics (counts come from the Record* methods).
func (m *RunMetrics) Advance(int) {}

// Log is unused for metrics (errors are captured via RecordService).
func (m *RunMetrics) Log(string) {}

// Stop finalizes the final stage. Idempotent.
func (m *RunMetrics) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.closeStageLocked()
	})
}

// closeStageLocked appends the elapsed time of the active stage; caller holds mu.
func (m *RunMetrics) closeStageLocked() {
	if m.curStage == "" {
		return
	}
	m.stages = append(m.stages, stageTiming{
		Name:   m.curStage,
		Millis: time.Since(m.stageStart).Milliseconds(),
	})
	m.curStage = ""
}

// --- detail recording ----------------------------------------------------

// SetCollectors overwrites the recorded collector set. Used by offline
// directory ingest, where the set of services is known only after the files are
// classified.
func (m *RunMetrics) SetCollectors(collectors []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.env.Collectors = collectors
	m.mu.Unlock()
}

// SetCollectUnits records the exact number of leaf collection units (the Collect
// stage's denominator), for context on the timings.
func (m *RunMetrics) SetCollectUnits(n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.collectUnits = n
	m.mu.Unlock()
}

// RecordBootstrap records an account's bootstrap (identity + region discovery)
// outcome and duration.
func (m *RunMetrics) RecordBootstrap(accountID, profile string, regions int, d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.accountLocked(accountID)
	a.Profile = profile
	a.Regions = regions
	a.BootstrapMillis = d.Milliseconds()
}

// RecordService records how long one service's Fetch+Ingest took on an account,
// and its error if any.
func (m *RunMetrics) RecordService(accountID, service string, d time.Duration, err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.serviceLocked(accountID, service)
	s.Millis = d.Milliseconds()
	if err != nil {
		s.Err = err.Error()
	}
}

// RecordRegion records one region worker's wall-clock for a service, keeping the
// per-service region count and slowest region for the summary.
func (m *RunMetrics) RecordRegion(accountID, service, region string, d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.serviceLocked(accountID, service)
	s.RegionCount++
	if ms := d.Milliseconds(); ms > s.SlowestRegionMillis {
		s.SlowestRegionMillis = ms
		s.SlowestRegion = region
	}
}

// RecordEdgeFamily records one edge family's build duration for the per-processor
// breakdown (the Go counterpart of AWSHound's wave_edge:<Processor> timings).
// Safe for concurrent use; families are appended in completion order.
func (m *RunMetrics) RecordEdgeFamily(name string, millis int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.edgeFamilies = append(m.edgeFamilies, stageTiming{Name: name, Millis: millis})
	m.mu.Unlock()
}

// SetAPIReport records request-level AWS API activity. The report is obtained
// from the run's shared API request controller after collection completes. A
// distinct setter keeps offline process/emit runs from serializing a misleading
// all-zero API section.
func (m *RunMetrics) SetAPIReport(api apireq.Report) {
	if m == nil {
		return
	}
	apiCopy := api
	apiCopy.Services = append([]apireq.ServiceReport(nil), api.Services...)
	for i := range apiCopy.Services {
		apiCopy.Services[i].Operations = append([]apireq.OperationReport(nil), api.Services[i].Operations...)
	}
	m.mu.Lock()
	m.apiReport = &apiCopy
	m.mu.Unlock()
}

// Finish records the final account count (authoritative, from the store, so it is
// correct for both live collection and offline directory ingest) and graph size.
func (m *RunMetrics) Finish(accounts, nodes, edges int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.accountsCount, m.nodes, m.edges = accounts, nodes, edges
	m.mu.Unlock()
}

// accountLocked / serviceLocked upsert entries; caller holds mu.
func (m *RunMetrics) accountLocked(accountID string) *accountMetric {
	a, ok := m.accounts[accountID]
	if !ok {
		a = &accountMetric{AccountID: accountID, services: map[string]*serviceMetric{}}
		m.accounts[accountID] = a
		m.acctOrder = append(m.acctOrder, accountID)
	}
	return a
}

func (m *RunMetrics) serviceLocked(accountID, service string) *serviceMetric {
	a := m.accountLocked(accountID)
	s, ok := a.services[service]
	if !ok {
		s = &serviceMetric{}
		a.services[service] = s
		a.svcOrder = append(a.svcOrder, service)
	}
	return s
}
