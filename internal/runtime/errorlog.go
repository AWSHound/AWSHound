package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// CollectError is one bootstrap or service-level collection failure. Region is
// currently always "" (errors are service-scoped); the field exists so a later
// per-region/per-resource capture can populate it without changing the schema.
type CollectError struct {
	AccountID string `json:"account_id"`
	Profile   string `json:"profile"`
	Service   string `json:"service"`
	Region    string `json:"region,omitempty"`
	Message   string `json:"message"`
}

// CollectErrorLog accumulates bootstrap and service-level collection errors
// across every account and service in a run. It is safe for concurrent use.
type CollectErrorLog struct {
	mu   sync.Mutex
	errs []CollectError
}

// NewCollectErrorLog returns an empty error log ready for concurrent Record calls.
func NewCollectErrorLog() *CollectErrorLog { return &CollectErrorLog{} }

// Record appends one collection error. Safe for concurrent use; a nil receiver is
// a no-op.
func (l *CollectErrorLog) Record(e CollectError) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.errs = append(l.errs, e)
	l.mu.Unlock()
}

// Len reports how many errors have been recorded. A nil receiver reports 0.
func (l *CollectErrorLog) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errs)
}

// CountsByService returns the number of errors recorded per service.
func (l *CollectErrorLog) CountsByService() map[string]int {
	counts := map[string]int{}
	if l == nil {
		return counts
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.errs {
		counts[e.Service]++
	}
	return counts
}

// SummaryByService renders the per-service counts as "svc:count, svc:count",
// ordered by service name, for a one-line summary. Returns "" when empty.
func (l *CollectErrorLog) SummaryByService() string {
	counts := l.CountsByService()
	if len(counts) == 0 {
		return ""
	}
	svcs := make([]string, 0, len(counts))
	for svc := range counts {
		svcs = append(svcs, svc)
	}
	sort.Strings(svcs)
	parts := make([]string, 0, len(svcs))
	for _, svc := range svcs {
		parts = append(parts, fmt.Sprintf("%s:%d", svc, counts[svc]))
	}
	return strings.Join(parts, ", ")
}

// collectErrorReport is the on-disk shape of the error log: a total, a per-service
// breakdown, and every individual error in the order they occurred.
type collectErrorReport struct {
	Total     int            `json:"total"`
	ByService map[string]int `json:"by_service"`
	Errors    []CollectError `json:"errors"`
}

// WriteJSON writes the accumulated errors to path as a structured report (total,
// per-service counts, and the full error list). It is a no-op returning nil when
// no errors were recorded, so callers can invoke it unconditionally without
// leaving an empty file behind on a clean run.
func (l *CollectErrorLog) WriteJSON(path string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.errs) == 0 {
		return nil
	}
	byService := map[string]int{}
	for _, e := range l.errs {
		byService[e.Service]++
	}
	report := collectErrorReport{
		Total:     len(l.errs),
		ByService: byService,
		Errors:    l.errs,
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
