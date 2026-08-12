package apireq

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestWrapHTTPClientCachedAndPreservesConfiguration(t *testing.T) {
	controller := New(Limits{}, nil)
	base := &http.Client{
		Timeout: 42 * time.Second,
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       http.NoBody,
			}, nil
		}),
	}

	first := controller.WrapHTTPClient(base)
	if first == base {
		t.Fatal("WrapHTTPClient mutated/reused the original client")
	}
	if got := controller.WrapHTTPClient(base); got != first {
		t.Fatal("WrapHTTPClient did not return its cached wrapper")
	}
	if got := controller.WrapHTTPClient(first); got != first {
		t.Fatal("wrapping an existing controller client was not idempotent")
	}
	if first.Timeout != base.Timeout {
		t.Fatalf("client timeout = %v, want %v", first.Timeout, base.Timeout)
	}
}

func TestWrapHTTPClientCountsRedirectRoundTrips(t *testing.T) {
	var calls atomic.Int64
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		status := http.StatusOK
		header := make(http.Header)
		if request.URL.Path == "/start" {
			status = http.StatusFound
			header.Set("Location", "/finish")
		}
		return &http.Response{
			StatusCode: status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	})
	controller := New(Limits{}, nil)
	client := controller.WrapHTTPClient(&http.Client{Transport: transport})

	ctx := middleware.WithServiceID(context.Background(), " KMS ")
	ctx = middleware.WithOperationName(ctx, " ListKeys ")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	report := controller.Report()
	if calls.Load() != 2 || report.AttemptsSent != 2 {
		t.Fatalf("underlying/report attempts = %d/%d, want 2/2", calls.Load(), report.AttemptsSent)
	}
	operation := onlyOperation(t, report, "kms", "ListKeys")
	if operation.AttemptsSent != 2 {
		t.Fatalf("operation attempts = %d, want 2", operation.AttemptsSent)
	}
}

func TestHardLimitIsStrictUnderConcurrency(t *testing.T) {
	const (
		maximum = int64(25)
		callers = 200
	)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	controller := New(Limits{MaxRequests: maximum}, cancel)
	var sent atomic.Int64
	client := controller.WrapHTTPClient(&http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		sent.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})})

	start := make(chan struct{})
	results := make(chan error, callers)
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)
			if err == nil {
				response, doErr := client.Do(request)
				err = doErr
				if response != nil {
					response.Body.Close()
				}
			}
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)

	var allowed int64
	for err := range results {
		if err == nil {
			allowed++
			continue
		}
		var limitErr *ErrLimitExceeded
		if !errors.As(err, &limitErr) {
			t.Fatalf("denied request error %T (%v), want ErrLimitExceeded", err, err)
		}
	}
	if allowed != maximum || sent.Load() != maximum {
		t.Fatalf("allowed/sent = %d/%d, want %d/%d", allowed, sent.Load(), maximum, maximum)
	}
	report := controller.Report()
	if report.AttemptsSent != maximum || !report.LimitExceeded {
		t.Fatalf("report attempts/limitExceeded = %d/%v, want %d/true", report.AttemptsSent, report.LimitExceeded, maximum)
	}
	var limitErr *ErrLimitExceeded
	if !errors.As(controller.Err(), &limitErr) || limitErr.Maximum != maximum {
		t.Fatalf("controller.Err() = %#v, want maximum %d", controller.Err(), maximum)
	}
	if !errors.As(context.Cause(ctx), &limitErr) {
		t.Fatalf("cancellation cause %T, want ErrLimitExceeded", context.Cause(ctx))
	}
}

func TestRollingRateLimitWaitsForOldestAttempt(t *testing.T) {
	controller := New(Limits{MaxRequestsPerMinute: 2}, nil)
	controller.window = 35 * time.Millisecond
	client := controller.WrapHTTPClient(&http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
	})})

	started := time.Now()
	for i := 0; i < 3; i++ {
		request, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	elapsed := time.Since(started)
	if elapsed < 25*time.Millisecond {
		t.Fatalf("three requests with a two-request window completed in %v", elapsed)
	}
	report := controller.Report()
	if report.AttemptsSent != 3 {
		t.Fatalf("attempts sent = %d, want 3", report.AttemptsSent)
	}
	if report.LimiterWaitMillis < 20 {
		t.Fatalf("limiter wait = %dms, want at least 20ms", report.LimiterWaitMillis)
	}
}

func TestCanceledRateWaitDoesNotConsumeBudget(t *testing.T) {
	controller := New(Limits{MaxRequestsPerMinute: 1}, nil)
	controller.window = time.Second
	client := controller.WrapHTTPClient(&http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
	})})

	first, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	response, err := client.Do(first)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	second, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
	_, err = client.Do(second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second request error = %v, want deadline exceeded", err)
	}
	if report := controller.Report(); report.AttemptsSent != 1 || report.LimiterWaitMillis == 0 {
		t.Fatalf("attempts/wait after cancellation = %d/%dms, want 1/nonzero", report.AttemptsSent, report.LimiterWaitMillis)
	}
}

func TestAPIOptionRecordsLogicalOutcomesAndSortedBreakdown(t *testing.T) {
	controller := New(Limits{}, nil)
	retryer := retry.NewStandard(func(options *retry.StandardOptions) {
		options.MaxAttempts = 2
		options.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
	})

	runOperation(t, controller, retryer, "KMS", "ListKeys",
		&smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"}, nil)
	runOperation(t, controller, retryer, "CloudFormation", "DescribeStacks", context.Canceled)
	runOperation(t, controller, retryer, "KMS", "GetKeyPolicy",
		&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"})

	report := controller.Report()
	if report.LogicalCalls != 3 || report.Retries != 0 || report.Successes != 1 || report.Failures != 2 {
		t.Fatalf("logical/retries/success/failure = %d/%d/%d/%d, want 3/0/1/2",
			report.LogicalCalls, report.Retries, report.Successes, report.Failures)
	}
	if report.APIErrors != 0 || report.TransportErrors != 0 || report.Throttles != 0 {
		t.Fatalf("pre-transport api/transport/throttles = %d/%d/%d, want 0/0/0",
			report.APIErrors, report.TransportErrors, report.Throttles)
	}
	if len(report.Services) != 2 || report.Services[0].Name != "cloudformation" || report.Services[1].Name != "kms" {
		t.Fatalf("service ordering = %#v", report.Services)
	}
	if got := report.Services[1].Operations; len(got) != 2 || got[0].Name != "GetKeyPolicy" || got[1].Name != "ListKeys" {
		t.Fatalf("operation ordering = %#v", got)
	}
	if got := controller.Report(); got.Limits != (Limits{}) || got.LimitExceeded {
		t.Fatalf("unexpected limits snapshot: %#v", got)
	}
}

func TestAWSClientEndToEndRetryAndThrottleBreakdown(t *testing.T) {
	controller := New(Limits{}, nil)
	var sent atomic.Int64
	base := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		attempt := sent.Add(1)
		status := http.StatusOK
		body := `{"Keys":[]}`
		if attempt == 1 {
			status = http.StatusBadRequest
			body = `{"__type":"ThrottlingException","message":"slow down"}`
		}
		return &http.Response{
			StatusCode: status,
			Header: http.Header{
				"Content-Type":     []string{"application/x-amz-json-1.1"},
				"X-Amzn-Requestid": []string{"request-id"},
			},
			Body:    io.NopCloser(strings.NewReader(body)),
			Request: request,
		}, nil
	})}
	retryer := retry.NewStandard(func(options *retry.StandardOptions) {
		options.MaxAttempts = 2
		options.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
	})
	client := kms.New(kms.Options{
		APIOptions:   []func(*middleware.Stack) error{controller.APIOption},
		BaseEndpoint: aws.String("https://kms.us-east-1.amazonaws.com"),
		Credentials:  credentials.NewStaticCredentialsProvider("access-key", "secret-key", ""),
		HTTPClient:   controller.WrapHTTPClient(base),
		Region:       "us-east-1",
		Retryer:      retryer,
	})

	if _, err := client.ListKeys(context.Background(), &kms.ListKeysInput{}); err != nil {
		t.Fatal(err)
	}
	report := controller.Report()
	if report.LogicalCalls != 1 || report.AttemptsSent != 2 || report.Retries != 1 || report.Successes != 1 || report.Failures != 0 {
		t.Fatalf("logical/attempts/retries/success/failure = %d/%d/%d/%d/%d, want 1/2/1/1/0",
			report.LogicalCalls, report.AttemptsSent, report.Retries, report.Successes, report.Failures)
	}
	if report.APIErrors != 1 || report.TransportErrors != 0 || report.Throttles != 1 {
		t.Fatalf("api/transport/throttles = %d/%d/%d, want 1/0/1",
			report.APIErrors, report.TransportErrors, report.Throttles)
	}
	if len(report.Services) != 1 || len(report.Services[0].Operations) != 1 {
		t.Fatalf("HTTP and SDK middleware did not aggregate under one service/operation: %#v", report.Services)
	}
	operation := onlyOperation(t, report, "kms", "ListKeys")
	if operation.AttemptsSent != 2 || operation.Retries != 1 || operation.APIErrors != 1 || operation.Throttles != 1 {
		t.Fatalf("unexpected operation report: %#v", operation)
	}
}

func TestNestedSDKFailureIsNotAttributedToParentOperation(t *testing.T) {
	controller := New(Limits{}, nil)
	base := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
			Body:       io.NopCloser(strings.NewReader(`{"__type":"AccessDeniedException","message":"denied"}`)),
			Request:    request,
		}, nil
	})}
	inner := kms.New(kms.Options{
		APIOptions:   []func(*middleware.Stack) error{controller.APIOption},
		BaseEndpoint: aws.String("https://kms.us-east-1.amazonaws.com"),
		Credentials:  credentials.NewStaticCredentialsProvider("access-key", "secret-key", ""),
		HTTPClient:   controller.WrapHTTPClient(base),
		Region:       "us-east-1",
		Retryer: retry.NewStandard(func(options *retry.StandardOptions) {
			options.MaxAttempts = 1
		}),
	})

	// Credential providers can make a nested SDK call while a parent service is
	// trying to sign. Model that nesting directly: only the inner KMS request
	// reaches HTTP, though the outer IAM logical call also fails.
	stack := middleware.NewStack("ListUsers", func() interface{} { return struct{}{} })
	if err := controller.APIOption(stack); err != nil {
		t.Fatal(err)
	}
	tracker, ok := stack.Finalize.Get(controllerMiddlewareID)
	if !ok {
		t.Fatal("API option did not add controller middleware")
	}
	ctx := middleware.WithServiceID(context.Background(), "IAM")
	ctx = middleware.WithOperationName(ctx, "ListUsers")
	_, _, _ = tracker.HandleFinalize(ctx, middleware.FinalizeInput{Request: struct{}{}}, middleware.FinalizeHandlerFunc(
		func(ctx context.Context, _ middleware.FinalizeInput) (middleware.FinalizeOutput, middleware.Metadata, error) {
			_, err := inner.ListKeys(ctx, &kms.ListKeysInput{})
			return middleware.FinalizeOutput{}, middleware.Metadata{}, err
		},
	))

	report := controller.Report()
	iam := onlyOperation(t, report, "iam", "ListUsers")
	if iam.LogicalCalls != 1 || iam.Failures != 1 || iam.AttemptsSent != 0 || iam.APIErrors != 0 || iam.TransportErrors != 0 {
		t.Fatalf("parent operation misattributed nested request: %#v", iam)
	}
	kmsCall := onlyOperation(t, report, "kms", "ListKeys")
	if kmsCall.LogicalCalls != 1 || kmsCall.AttemptsSent != 1 || kmsCall.APIErrors != 1 {
		t.Fatalf("nested request report: %#v", kmsCall)
	}
}

func TestAWSClientRetryCannotCrossHardLimit(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	controller := New(Limits{MaxRequests: 1}, cancel)
	base := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header: http.Header{
				"Content-Type":     []string{"application/x-amz-json-1.1"},
				"X-Amzn-Requestid": []string{"request-id"},
			},
			Body:    io.NopCloser(strings.NewReader(`{"__type":"ThrottlingException","message":"slow down"}`)),
			Request: request,
		}, nil
	})}
	retryer := retry.NewStandard(func(options *retry.StandardOptions) {
		options.MaxAttempts = 3
		options.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
	})
	client := kms.New(kms.Options{
		APIOptions:   []func(*middleware.Stack) error{controller.APIOption},
		BaseEndpoint: aws.String("https://kms.us-east-1.amazonaws.com"),
		Credentials:  credentials.NewStaticCredentialsProvider("access-key", "secret-key", ""),
		HTTPClient:   controller.WrapHTTPClient(base),
		Region:       "us-east-1",
		Retryer:      retryer,
	})

	_, err := client.ListKeys(ctx, &kms.ListKeysInput{})
	var limitErr *ErrLimitExceeded
	if !errors.As(err, &limitErr) {
		t.Fatalf("SDK error %T (%v), want wrapped ErrLimitExceeded", err, err)
	}
	if !errors.As(context.Cause(ctx), &limitErr) {
		t.Fatalf("cancellation cause %T, want ErrLimitExceeded", context.Cause(ctx))
	}
	report := controller.Report()
	if report.AttemptsSent != 1 || report.Retries != 0 || report.LogicalCalls != 1 || report.Successes != 0 || report.Failures != 1 || !report.LimitExceeded {
		t.Fatalf("attempts/retries/logical/success/failure/exceeded = %d/%d/%d/%d/%d/%v, want 1/0/1/0/1/true",
			report.AttemptsSent, report.Retries, report.LogicalCalls, report.Successes, report.Failures, report.LimitExceeded)
	}
	if report.APIErrors != 1 || report.TransportErrors != 0 || report.Throttles != 1 {
		t.Fatalf("api/transport/throttles = %d/%d/%d, want 1/0/1",
			report.APIErrors, report.TransportErrors, report.Throttles)
	}
	operation := onlyOperation(t, report, "kms", "ListKeys")
	if operation.AttemptsSent != 1 || operation.Retries != 0 || operation.LogicalCalls != 1 || operation.APIErrors != 1 || operation.Throttles != 1 {
		t.Fatalf("unexpected operation report: %#v", operation)
	}
}

func runOperation(t *testing.T, controller *Controller, retryer *retry.Standard, service, operation string, results ...error) {
	t.Helper()
	stack := middleware.NewStack(operation, func() interface{} { return struct{}{} })
	if err := controller.APIOption(stack); err != nil {
		t.Fatal(err)
	}
	tracker, ok := stack.Finalize.Get(controllerMiddlewareID)
	if !ok {
		t.Fatal("API option did not add controller middleware")
	}
	attempts := retry.NewAttemptMiddleware(retryer, func(value interface{}) interface{} { return value })
	index := 0
	operationHandler := middleware.FinalizeHandlerFunc(func(context.Context, middleware.FinalizeInput) (middleware.FinalizeOutput, middleware.Metadata, error) {
		if index >= len(results) {
			t.Fatal("SDK retry middleware made too many attempts")
		}
		err := results[index]
		index++
		return middleware.FinalizeOutput{}, middleware.Metadata{}, err
	})
	retryHandler := middleware.FinalizeHandlerFunc(func(ctx context.Context, input middleware.FinalizeInput) (middleware.FinalizeOutput, middleware.Metadata, error) {
		return attempts.HandleFinalize(ctx, input, operationHandler)
	})
	ctx := middleware.WithServiceID(context.Background(), service)
	ctx = middleware.WithOperationName(ctx, operation)
	_, _, _ = tracker.HandleFinalize(ctx, middleware.FinalizeInput{Request: struct{}{}}, retryHandler)
	if index != len(results) {
		t.Fatalf("SDK retry middleware attempts = %d, want %d", index, len(results))
	}
}

func onlyOperation(t *testing.T, report Report, service, operation string) OperationReport {
	t.Helper()
	for _, sr := range report.Services {
		if sr.Name != service {
			continue
		}
		for _, or := range sr.Operations {
			if or.Name == operation {
				return or
			}
		}
	}
	t.Fatalf("did not find %s/%s in %#v", service, operation, report)
	return OperationReport{}
}
