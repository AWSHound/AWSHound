package apireq

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	controllerMiddlewareID = "awshoundAPIRequestMetrics"
	unknownMetricName      = "unknown"
)

// ErrLimitExceeded is returned, and used as the collection cancellation
// cause, when another request would exceed the configured hard request limit.
type ErrLimitExceeded struct {
	Maximum int64
}

func (e *ErrLimitExceeded) Error() string {
	return fmt.Sprintf("AWS API request limit exceeded (maximum %d)", e.Maximum)
}

// Controller owns the request budget, rolling rate window, and metrics for a
// single collection run. Controllers must be constructed with New.
type Controller struct {
	mu sync.Mutex

	limits Limits
	cancel context.CancelCauseFunc
	err    error

	window         time.Duration
	windowAttempts []time.Time
	wrappedClients map[*http.Client]*http.Client
	totals         counters
	services       map[string]*serviceCounters
}

// logicalCallState is scoped to one SDK operation invocation. Nested credential
// provider calls install their own state, so a failed STS AssumeRole does not get
// counted again as an API failure on the parent service whose signing triggered
// credential resolution.
type logicalCallState struct {
	attemptsSent atomic.Int64
}

type logicalCallStateKey struct{}

type counters struct {
	logicalCalls    int64
	attemptsSent    int64
	retries         int64
	successes       int64
	failures        int64
	apiErrors       int64
	transportErrors int64
	throttles       int64
	limiterWait     time.Duration
	attemptTotal    time.Duration
	attemptMax      time.Duration
}

type serviceCounters struct {
	counters
	operations map[string]*counters
}

// New constructs a run-scoped controller. Non-positive limit values disable
// their corresponding limit.
func New(limits Limits, cancel context.CancelCauseFunc) *Controller {
	if limits.MaxRequests < 0 {
		limits.MaxRequests = 0
	}
	if limits.MaxRequestsPerMinute < 0 {
		limits.MaxRequestsPerMinute = 0
	}
	return &Controller{
		limits:         limits,
		cancel:         cancel,
		window:         time.Minute,
		wrappedClients: make(map[*http.Client]*http.Client),
		services:       make(map[string]*serviceCounters),
	}
}

// WrapHTTPClient returns a cached shallow copy of client whose transport
// applies the run-wide limit and records each HTTP attempt. The original
// client is not mutated. Requests must also use APIOption to record logical
// SDK call results and error classifications.
func (c *Controller) WrapHTTPClient(client *http.Client) *http.Client {
	if c == nil {
		return client
	}
	if client == nil {
		client = http.DefaultClient
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if wrapped, ok := c.wrappedClients[client]; ok {
		return wrapped
	}
	if transport, ok := client.Transport.(*requestTransport); ok && transport.controller == c {
		c.wrappedClients[client] = client
		return client
	}

	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	copy := *client
	copy.Transport = &requestTransport{controller: c, next: base}
	wrapped := &copy
	c.wrappedClients[client] = wrapped
	c.wrappedClients[wrapped] = wrapped
	return wrapped
}

// APIOption adds an outer finalize middleware that observes exactly one
// logical SDK operation. The HTTP wrapper marks which retry results were
// actually sent so pre-transport and nested credential failures are not
// misclassified as requests to the parent service.
func (c *Controller) APIOption(stack *middleware.Stack) error {
	if c == nil {
		return nil
	}
	if _, ok := stack.Finalize.Get(controllerMiddlewareID); ok {
		return nil
	}
	return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc(
		controllerMiddlewareID,
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
			middleware.FinalizeOutput, middleware.Metadata, error,
		) {
			service, operation := normalizedContextNames(ctx)
			state := &logicalCallState{}
			out, metadata, err := next.HandleFinalize(context.WithValue(ctx, logicalCallStateKey{}, state), in)
			// CancelCause can win a race with net/http's return path and replace
			// the typed transport error with context.Canceled. Reattach the
			// controller error outside the entire retry loop so callers can still
			// identify a policy stop through normal SDK error wrapping.
			if err != nil {
				if limitErr := c.Err(); limitErr != nil {
					var alreadyTyped *ErrLimitExceeded
					if !errors.As(err, &alreadyTyped) {
						err = errors.Join(err, limitErr)
					}
				}
			}
			c.recordLogical(service, operation, state.attemptsSent.Load(), metadata, err)
			return out, metadata, err
		},
	), middleware.Before)
}

// Err returns the first hard request-limit error, if any.
func (c *Controller) Err() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Report returns a point-in-time, deeply copied metrics snapshot. Service and
// operation entries are sorted by name for stable JSON output.
func (c *Controller) Report() Report {
	if c == nil {
		return Report{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	report := reportFromCounters(c.totals)
	report.Limits = c.limits
	report.LimitExceeded = c.err != nil
	report.Services = make([]ServiceReport, 0, len(c.services))
	for service, value := range c.services {
		sr := serviceReportFromCounters(service, value.counters)
		sr.Operations = make([]OperationReport, 0, len(value.operations))
		for operation, operationCounters := range value.operations {
			sr.Operations = append(sr.Operations, operationReportFromCounters(operation, *operationCounters))
		}
		sort.Slice(sr.Operations, func(i, j int) bool {
			return sr.Operations[i].Name < sr.Operations[j].Name
		})
		report.Services = append(report.Services, sr)
	}
	sort.Slice(report.Services, func(i, j int) bool {
		return report.Services[i].Name < report.Services[j].Name
	})
	return report
}

type requestTransport struct {
	controller *Controller
	next       http.RoundTripper
}

func (t *requestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	service, operation := normalizedContextNames(request.Context())
	if err := t.controller.acquire(request.Context(), service, operation, isSDKRetry(request)); err != nil {
		return nil, err
	}
	if state, _ := request.Context().Value(logicalCallStateKey{}).(*logicalCallState); state != nil {
		state.attemptsSent.Add(1)
	}
	started := time.Now()
	response, err := t.next.RoundTrip(request)
	t.controller.recordAttemptDuration(service, operation, time.Since(started))
	return response, err
}

func (c *Controller) acquire(ctx context.Context, service, operation string, sdkRetry bool) error {
	for {
		now := time.Now()
		c.mu.Lock()
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return err
		}
		if c.limits.MaxRequests > 0 && c.totals.attemptsSent >= c.limits.MaxRequests {
			err := &ErrLimitExceeded{Maximum: c.limits.MaxRequests}
			c.err = err
			cancel := c.cancel
			c.mu.Unlock()
			if cancel != nil {
				cancel(err)
			}
			return err
		}

		c.pruneWindowLocked(now)
		if c.limits.MaxRequestsPerMinute <= 0 || len(c.windowAttempts) < c.limits.MaxRequestsPerMinute {
			if c.limits.MaxRequestsPerMinute > 0 {
				c.windowAttempts = append(c.windowAttempts, now)
			}
			c.addLocked(service, operation, func(value *counters) {
				value.attemptsSent++
				if sdkRetry {
					value.retries++
				}
			})
			c.mu.Unlock()
			return nil
		}

		wake := c.windowAttempts[0].Add(c.window)
		c.mu.Unlock()

		startedWaiting := time.Now()
		timer := time.NewTimer(time.Until(wake))
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			c.recordLimiterWait(service, operation, time.Since(startedWaiting))
			if err := c.Err(); err != nil {
				return err
			}
			if cause := context.Cause(ctx); cause != nil {
				return cause
			}
			return ctx.Err()
		}
		c.recordLimiterWait(service, operation, time.Since(startedWaiting))
	}
}

func (c *Controller) pruneWindowLocked(now time.Time) {
	cutoff := now.Add(-c.window)
	first := 0
	for first < len(c.windowAttempts) && !c.windowAttempts[first].After(cutoff) {
		first++
	}
	if first == 0 {
		return
	}
	if first == len(c.windowAttempts) {
		c.windowAttempts = c.windowAttempts[:0]
		return
	}
	remaining := len(c.windowAttempts) - first
	if first >= remaining {
		copy(c.windowAttempts, c.windowAttempts[first:])
		c.windowAttempts = c.windowAttempts[:remaining]
	} else {
		c.windowAttempts = c.windowAttempts[first:]
	}
}

func (c *Controller) recordLogical(service, operation string, attemptsSent int64, metadata middleware.Metadata, finalErr error) {
	results, haveResults := retry.GetAttemptResults(metadata)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addLocked(service, operation, func(value *counters) {
		value.logicalCalls++
		if finalErr == nil {
			value.successes++
		} else {
			value.failures++
		}
		if attemptsSent == 0 {
			return
		}
		if !haveResults || len(results.Results) == 0 {
			recordAttemptError(value, finalErr)
			return
		}
		for i, result := range results.Results {
			// The retry middleware can create a result for a local budget denial,
			// credential/signing failure, or another pre-transport error. Only
			// classify results that reached this operation's wrapped HTTP client.
			if int64(i) >= attemptsSent {
				break
			}
			recordAttemptError(value, result.Err)
		}
	})
}

func (c *Controller) recordAttemptDuration(service, operation string, elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addLocked(service, operation, func(value *counters) {
		value.attemptTotal += elapsed
		if elapsed > value.attemptMax {
			value.attemptMax = elapsed
		}
	})
}

func (c *Controller) recordLimiterWait(service, operation string, elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addLocked(service, operation, func(value *counters) {
		value.limiterWait += elapsed
	})
}

func (c *Controller) addLocked(service, operation string, update func(*counters)) {
	update(&c.totals)
	serviceValue, ok := c.services[service]
	if !ok {
		serviceValue = &serviceCounters{operations: make(map[string]*counters)}
		c.services[service] = serviceValue
	}
	update(&serviceValue.counters)
	operationValue, ok := serviceValue.operations[operation]
	if !ok {
		operationValue = &counters{}
		serviceValue.operations[operation] = operationValue
	}
	update(operationValue)
}

func recordAttemptError(value *counters, err error) {
	if err == nil {
		return
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		value.apiErrors++
		if isThrottle(err) {
			value.throttles++
		}
		return
	}
	var responseErr interface{ HTTPStatusCode() int }
	if errors.As(err, &responseErr) {
		value.apiErrors++
		if responseErr.HTTPStatusCode() == http.StatusTooManyRequests {
			value.throttles++
		}
		return
	}
	var limitErr *ErrLimitExceeded
	if errors.As(err, &limitErr) {
		return
	}
	value.transportErrors++
}

// isSDKRetry identifies a retry that reached the HTTP transport from the
// retry-attempt metadata applied by aws-sdk-go-v2. Redirects remain attempts but
// are not mislabeled as SDK retries.
func isSDKRetry(request *http.Request) bool {
	for _, header := range request.Header.Values("Amz-Sdk-Request") {
		for _, part := range strings.Split(header, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || !strings.EqualFold(key, "attempt") {
				continue
			}
			attempt, err := strconv.Atoi(strings.TrimSpace(value))
			return err == nil && attempt > 1
		}
	}
	return false
}

func isThrottle(err error) bool {
	if retry.IsErrorThrottles(retry.DefaultThrottles).IsErrorThrottle(err).Bool() {
		return true
	}
	var responseErr *smithyhttp.ResponseError
	return errors.As(err, &responseErr) && responseErr.HTTPStatusCode() == http.StatusTooManyRequests
}

func normalizedContextNames(ctx context.Context) (service, operation string) {
	service = awsmiddleware.GetServiceID(ctx)
	operation = awsmiddleware.GetOperationName(ctx)
	if service == "" {
		service = middleware.GetServiceID(ctx)
	}
	if operation == "" {
		operation = middleware.GetOperationName(ctx)
	}
	return normalizeService(service), normalizeOperation(operation)
}

func normalizeService(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return unknownMetricName
	}
	var result strings.Builder
	result.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
			result.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			result.WriteRune(r)
		}
	}
	if result.Len() == 0 {
		return unknownMetricName
	}
	return result.String()
}

func normalizeOperation(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return unknownMetricName
}

func reportFromCounters(value counters) Report {
	return Report{
		LogicalCalls:       value.logicalCalls,
		AttemptsSent:       value.attemptsSent,
		Retries:            value.retries,
		Successes:          value.successes,
		Failures:           value.failures,
		APIErrors:          value.apiErrors,
		TransportErrors:    value.transportErrors,
		Throttles:          value.throttles,
		LimiterWaitMillis:  value.limiterWait.Milliseconds(),
		AttemptMillisTotal: value.attemptTotal.Milliseconds(),
		AttemptMillisMax:   value.attemptMax.Milliseconds(),
	}
}

func serviceReportFromCounters(name string, value counters) ServiceReport {
	return ServiceReport{
		Name:               name,
		LogicalCalls:       value.logicalCalls,
		AttemptsSent:       value.attemptsSent,
		Retries:            value.retries,
		Successes:          value.successes,
		Failures:           value.failures,
		APIErrors:          value.apiErrors,
		TransportErrors:    value.transportErrors,
		Throttles:          value.throttles,
		LimiterWaitMillis:  value.limiterWait.Milliseconds(),
		AttemptMillisTotal: value.attemptTotal.Milliseconds(),
		AttemptMillisMax:   value.attemptMax.Milliseconds(),
	}
}

func operationReportFromCounters(name string, value counters) OperationReport {
	return OperationReport{
		Name:               name,
		LogicalCalls:       value.logicalCalls,
		AttemptsSent:       value.attemptsSent,
		Retries:            value.retries,
		Successes:          value.successes,
		Failures:           value.failures,
		APIErrors:          value.apiErrors,
		TransportErrors:    value.transportErrors,
		Throttles:          value.throttles,
		LimiterWaitMillis:  value.limiterWait.Milliseconds(),
		AttemptMillisTotal: value.attemptTotal.Milliseconds(),
		AttemptMillisMax:   value.attemptMax.Milliseconds(),
	}
}
