package metrics

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/AWSHound/AWSHound/internal/apireq"
)

// Summary renders a human-readable run report, modeled on AWSHound's PIPELINE
// METRICS table: overall counters, the pipeline stages with their share of total
// time, and — nested under the build — the per-edge-family breakdown sorted slowest
// first. Nil-safe: a nil receiver returns "". Callers print this to stderr at the
// end of a --metrics run so the timings are visible without opening the JSON.
func (m *RunMetrics) Summary() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	total := time.Since(m.started).Milliseconds()
	var b strings.Builder
	b.WriteString("\n================================================================\n")
	b.WriteString("  PIPELINE METRICS\n")
	b.WriteString("================================================================\n\n")
	fmt.Fprintf(&b, "  accounts.............................. %12s\n", commaInt(m.accountsCount))
	fmt.Fprintf(&b, "  nodes................................. %12s\n", commaInt(m.nodes))
	fmt.Fprintf(&b, "  edges................................. %12s\n", commaInt(m.edges))
	b.WriteString("\n")
	fmt.Fprintf(&b, "  %-32s %10s %7s\n", "Stage", "Time", "%")
	fmt.Fprintf(&b, "  %-32s %10s %7s\n", strings.Repeat("-", 32), strings.Repeat("-", 10), strings.Repeat("-", 7))
	for _, st := range m.stages {
		fmt.Fprintf(&b, "  %-32s %10s %6s%%\n", st.Name, secs(st.Millis), pct(st.Millis, total))
		// Nest the edge-family breakdown under the build-edges stage, slowest first.
		if isEdgeStage(st.Name) && len(m.edgeFamilies) > 0 {
			fams := append([]stageTiming(nil), m.edgeFamilies...)
			sort.SliceStable(fams, func(i, j int) bool { return fams[i].Millis > fams[j].Millis })
			for _, f := range fams {
				fmt.Fprintf(&b, "    edge:%-29s %10s\n", f.Name, secs(f.Millis))
			}
		}
	}
	fmt.Fprintf(&b, "  %-32s %10s %7s\n", strings.Repeat("-", 32), strings.Repeat("-", 10), strings.Repeat("-", 7))
	fmt.Fprintf(&b, "  %-32s %10s\n", "TOTAL", secs(total))
	writeAPISummary(&b, m.apiReport)
	b.WriteString("================================================================\n")
	return b.String()
}

// writeAPISummary renders transmitted requests rather than only logical SDK
// calls, because every retry and paginator page consumes AWS API capacity. It
// includes service aggregates and their operation breakdown so expensive or
// throttled APIs are immediately visible in the terminal report.
func writeAPISummary(b *strings.Builder, api *apireq.Report) {
	if api == nil {
		return
	}

	b.WriteString("\n  AWS API REQUESTS\n\n")
	fmt.Fprintf(b, "  logical calls........................ %12s\n", commaInt64(api.LogicalCalls))
	fmt.Fprintf(b, "  attempts sent........................ %12s\n", commaInt64(api.AttemptsSent))
	fmt.Fprintf(b, "  successful calls..................... %12s\n", commaInt64(api.Successes))
	fmt.Fprintf(b, "  failed calls......................... %12s\n", commaInt64(api.Failures))
	fmt.Fprintf(b, "  retries.............................. %12s\n", commaInt64(api.Retries))
	fmt.Fprintf(b, "  throttles............................ %12s\n", commaInt64(api.Throttles))
	fmt.Fprintf(b, "  API errors........................... %12s\n", commaInt64(api.APIErrors))
	fmt.Fprintf(b, "  transport errors..................... %12s\n", commaInt64(api.TransportErrors))
	fmt.Fprintf(b, "  limiter wait......................... %12s\n", secs(api.LimiterWaitMillis))
	fmt.Fprintf(b, "  total request limit.................. %12s\n", requestLimit(api.AttemptsSent, api.Limits.MaxRequests))
	fmt.Fprintf(b, "  requests/minute limit................ %12s\n", rateLimit(api.Limits.MaxRequestsPerMinute))
	if api.LimitExceeded {
		fmt.Fprintf(b, "  request limit exceeded............... %12s\n", "yes")
	}

	services := append([]apireq.ServiceReport(nil), api.Services...)
	sort.SliceStable(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	if len(services) == 0 {
		return
	}

	b.WriteString("\n")
	fmt.Fprintf(b, "  %-32s %9s %10s %9s %8s %10s %9s %12s %12s\n", "Service / operation", "Calls", "Attempts", "Retries", "Failed", "Throttles", "Errors", "Avg HTTP", "Max HTTP")
	fmt.Fprintf(b, "  %-32s %9s %10s %9s %8s %10s %9s %12s %12s\n", strings.Repeat("-", 32), strings.Repeat("-", 9), strings.Repeat("-", 10), strings.Repeat("-", 9), strings.Repeat("-", 8), strings.Repeat("-", 10), strings.Repeat("-", 9), strings.Repeat("-", 12), strings.Repeat("-", 12))
	writeAPIRow(b, "TOTAL", api.LogicalCalls, api.AttemptsSent, api.Retries, api.Failures, api.Throttles, api.APIErrors+api.TransportErrors, api.AttemptMillisTotal, api.AttemptMillisMax)
	for _, svc := range services {
		writeAPIRow(b, svc.Name, svc.LogicalCalls, svc.AttemptsSent, svc.Retries, svc.Failures, svc.Throttles, svc.APIErrors+svc.TransportErrors, svc.AttemptMillisTotal, svc.AttemptMillisMax)
		operations := append([]apireq.OperationReport(nil), svc.Operations...)
		sort.SliceStable(operations, func(i, j int) bool { return operations[i].Name < operations[j].Name })
		for _, op := range operations {
			writeAPIRow(b, "  "+op.Name, op.LogicalCalls, op.AttemptsSent, op.Retries, op.Failures, op.Throttles, op.APIErrors+op.TransportErrors, op.AttemptMillisTotal, op.AttemptMillisMax)
		}
	}
}

func writeAPIRow(b *strings.Builder, name string, calls, attempts, retries, failures, throttles, errors, totalMillis, maxMillis int64) {
	fmt.Fprintf(b, "  %-32s %9s %10s %9s %8s %10s %9s %12s %12s\n",
		name, commaInt64(calls), commaInt64(attempts), commaInt64(retries), commaInt64(failures), commaInt64(throttles), commaInt64(errors), avgMillis(totalMillis, attempts), millis(maxMillis))
}

func isEdgeStage(name string) bool {
	return strings.Contains(strings.ToLower(name), "edge")
}

// secs formats milliseconds as seconds with two decimals ("493.00s").
func secs(millis int64) string {
	return fmt.Sprintf("%.2fs", float64(millis)/1000)
}

// pct formats part/total as a one-decimal percentage; total==0 yields "0.0".
func pct(part, total int64) string {
	if total == 0 {
		return "0.0"
	}
	return fmt.Sprintf("%.1f", 100*float64(part)/float64(total))
}

// commaInt formats an int with thousands separators ("1,376,339").
func commaInt(n int) string {
	return commaInt64(int64(n))
}

func commaInt64(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func millis(n int64) string {
	return fmt.Sprintf("%dms", n)
}

func avgMillis(total, count int64) string {
	if count == 0 {
		return "0.0ms"
	}
	return fmt.Sprintf("%.1fms", float64(total)/float64(count))
}

func requestLimit(attempts, limit int64) string {
	if limit == 0 {
		return "unlimited"
	}
	return commaInt64(attempts) + "/" + commaInt64(limit)
}

func rateLimit(limit int) string {
	if limit == 0 {
		return "unlimited"
	}
	return commaInt(limit)
}
