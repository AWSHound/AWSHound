package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/apireq"
	"github.com/AWSHound/AWSHound/internal/metrics"
)

type apiMetricsRoundTripper func(*http.Request) (*http.Response, error)

func (f apiMetricsRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestStopForAPILimitPersistsFinalRequestReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	ctx, cancel, controller := newAPIController(context.Background(), path, 1, 0)
	defer cancel(nil)
	client := controller.WrapHTTPClient(&http.Client{Transport: apiMetricsRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	})})

	for i := 0; i < 2; i++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, _ := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
	}

	runMetrics := metrics.New(metrics.Environment{})
	runMetrics.Stage("Collect", 1)
	if !stopForAPILimit(runMetrics, runMetrics, path, controller, 1) {
		t.Fatal("stopForAPILimit did not identify the controller error")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		AWSAPI apireq.Report `json:"awsApi"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.AWSAPI.AttemptsSent != 1 || !report.AWSAPI.LimitExceeded {
		t.Fatalf("persisted API report = %#v", report.AWSAPI)
	}
}

func TestAPIRequestInstrumentationActivation(t *testing.T) {
	ctx, cancel, controller := newAPIController(context.Background(), "", 0, 0)
	if controller != nil || context.Cause(ctx) != nil {
		t.Fatalf("unrequested instrumentation controller/cause = %#v/%v", controller, context.Cause(ctx))
	}
	cancel(nil)
	_, cancel, controller = newAPIController(context.Background(), "metrics.json", 0, 0)
	cancel(nil)
	if controller == nil {
		t.Fatal("--metrics did not enable request instrumentation")
	}
	if err := validateAPILimits(-1, 0); err == nil {
		t.Fatal("negative total limit accepted")
	}
	if err := validateAPILimits(0, -1); err == nil {
		t.Fatal("negative rate limit accepted")
	}
}
