package main

import (
	"context"
	"fmt"
	"os"

	"github.com/AWSHound/AWSHound/internal/apireq"
	"github.com/AWSHound/AWSHound/internal/metrics"
	"github.com/AWSHound/AWSHound/internal/progress"
)

// newAPIController creates the one request controller shared by every AWS
// session in a live run. Request instrumentation is opt-in with --metrics; the
// controller is also required when either hard limit is enabled so enforcement
// does not depend on writing a report.
func newAPIController(parent context.Context, metricsOut string, maxRequests int64, maxPerMinute int) (context.Context, context.CancelCauseFunc, *apireq.Controller) {
	ctx, cancel := context.WithCancelCause(parent)
	if metricsOut == "" && maxRequests == 0 && maxPerMinute == 0 {
		return ctx, cancel, nil
	}
	return ctx, cancel, apireq.New(apireq.Limits{
		MaxRequests:          maxRequests,
		MaxRequestsPerMinute: maxPerMinute,
	}, cancel)
}

func validateAPILimits(maxRequests int64, maxPerMinute int) error {
	if maxRequests < 0 {
		return fmt.Errorf("--max-api-requests must be >= 0")
	}
	if maxPerMinute < 0 {
		return fmt.Errorf("--max-api-requests-per-minute must be >= 0")
	}
	return nil
}

// writeMetrics closes the active stage, captures final AWS request activity,
// writes the sidecar, and optionally prints its human summary. It is shared by
// successful and policy-stopped paths so an API budget exhaustion is observable.
func writeMetrics(reporter progress.Reporter, m *metrics.RunMetrics, metricsOut string, api *apireq.Controller, accounts, nodes, edges int, printSummary bool) error {
	reporter.Stop()
	if m == nil || metricsOut == "" {
		return nil
	}
	if api != nil {
		m.SetAPIReport(api.Report())
	}
	m.Finish(accounts, nodes, edges)
	if err := m.WriteJSON(metricsOut); err != nil {
		return err
	}
	if printSummary {
		fmt.Fprint(os.Stderr, m.Summary())
	}
	return nil
}

// stopForAPILimit finalizes metrics and reports a hard request-budget stop.
// The caller owns the exit so it can finish any command-specific error logging.
func stopForAPILimit(reporter progress.Reporter, m *metrics.RunMetrics, metricsOut string, api *apireq.Controller, accounts int) bool {
	if api == nil || api.Err() == nil {
		return false
	}
	if err := writeMetrics(reporter, m, metricsOut, api, accounts, 0, 0, true); err != nil {
		fmt.Fprintln(os.Stderr, "awshound: write metrics after API request limit:", err)
	}
	fmt.Fprintln(os.Stderr, "awshound:", api.Err())
	return true
}

// writePartialMetrics keeps request diagnostics available when a live command
// fails for a reason other than the total request budget. Fatal exits bypass
// defers, so error paths call this explicitly before handing control to fatal.
func writePartialMetrics(reporter progress.Reporter, m *metrics.RunMetrics, metricsOut string, api *apireq.Controller, accounts, nodes, edges int) {
	if err := writeMetrics(reporter, m, metricsOut, api, accounts, nodes, edges, true); err != nil {
		fmt.Fprintln(os.Stderr, "awshound: write partial metrics:", err)
	}
}
