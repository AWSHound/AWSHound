package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AWSHound/AWSHound/internal/apireq"
)

// TestWriteJSONCapturesStagesAndSlowest drives a RunMetrics through the same calls
// the pipeline makes and checks the written report: stage timings, per-account /
// per-service detail, and the derived "slowest" summary that points at the
// bottleneck of a long collect.
func TestWriteJSONCapturesStagesAndSlowest(t *testing.T) {
	m := New(Environment{
		Collectors:       []string{"ec2", "iam"},
		MaxConcurrency:   200,
		RetryMode:        "adaptive",
		RetryMaxAttempts: 10,
		NumCPU:           8,
	})

	// Stage timings come from Stage()/Stop() transitions.
	m.Stage("Bootstrap", 2)
	m.RecordBootstrap("111122223333", "prod", 3, 50*time.Millisecond)
	m.RecordBootstrap("444455556666", "dev", 1, 20*time.Millisecond)

	m.SetCollectUnits(7)
	m.Stage("Collect", 7)
	// prod/ec2 is the slow one, and within it us-east-1 is the slow region.
	m.RecordRegion("111122223333", "ec2", "us-east-1", 900*time.Millisecond)
	m.RecordRegion("111122223333", "ec2", "us-west-2", 100*time.Millisecond)
	m.RecordService("111122223333", "ec2", 950*time.Millisecond, nil)
	m.RecordService("111122223333", "iam", 40*time.Millisecond, nil)
	m.RecordService("444455556666", "iam", 30*time.Millisecond, nil)

	m.Stage("Build edges", 11)
	m.Finish(2, 120, 340)
	m.Stop()

	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := m.WriteJSON(path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var r struct {
		Environment struct {
			Collectors     []string `json:"collectors"`
			MaxConcurrency int      `json:"maxConcurrency"`
			RetryMode      string   `json:"retryMode"`
		} `json:"environment"`
		Counters struct {
			Accounts     int `json:"accounts"`
			CollectUnits int `json:"collectUnits"`
			Nodes        int `json:"nodes"`
			Edges        int `json:"edges"`
		} `json:"counters"`
		Stages []struct {
			Name   string `json:"name"`
			Millis int64  `json:"millis"`
		} `json:"stages"`
		Accounts []struct {
			AccountID string `json:"accountID"`
			Services  []struct {
				Name          string `json:"name"`
				Millis        int64  `json:"millis"`
				RegionCount   int    `json:"regionCount"`
				SlowestRegion string `json:"slowestRegion"`
			} `json:"services"`
		} `json:"accounts"`
		Summary struct {
			SlowestStage   *struct{ Name string } `json:"slowestStage"`
			SlowestService *struct {
				AccountID string `json:"accountID"`
				Service   string `json:"service"`
			} `json:"slowestService"`
			SlowestRegion *struct {
				Region string `json:"region"`
			} `json:"slowestRegion"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}

	if r.Environment.MaxConcurrency != 200 || r.Environment.RetryMode != "adaptive" {
		t.Errorf("environment not captured: %+v", r.Environment)
	}
	if r.Counters.Accounts != 2 || r.Counters.CollectUnits != 7 || r.Counters.Nodes != 120 || r.Counters.Edges != 340 {
		t.Errorf("counters wrong: %+v", r.Counters)
	}
	// All three stages recorded (Bootstrap, Collect, Build edges).
	if len(r.Stages) != 3 {
		t.Fatalf("got %d stages, want 3: %+v", len(r.Stages), r.Stages)
	}
	// ec2 on prod carried 2 regions with us-east-1 slowest.
	var ec2 *struct {
		Name          string `json:"name"`
		Millis        int64  `json:"millis"`
		RegionCount   int    `json:"regionCount"`
		SlowestRegion string `json:"slowestRegion"`
	}
	for ai := range r.Accounts {
		if r.Accounts[ai].AccountID != "111122223333" {
			continue
		}
		for si := range r.Accounts[ai].Services {
			if r.Accounts[ai].Services[si].Name == "ec2" {
				ec2 = &r.Accounts[ai].Services[si]
			}
		}
	}
	if ec2 == nil {
		t.Fatal("prod ec2 service missing from report")
	}
	if ec2.RegionCount != 2 || ec2.SlowestRegion != "us-east-1" {
		t.Errorf("ec2 region detail wrong: %+v", *ec2)
	}
	// Summary points at the real bottleneck.
	if r.Summary.SlowestService == nil || r.Summary.SlowestService.Service != "ec2" || r.Summary.SlowestService.AccountID != "111122223333" {
		t.Errorf("slowestService wrong: %+v", r.Summary.SlowestService)
	}
	if r.Summary.SlowestRegion == nil || r.Summary.SlowestRegion.Region != "us-east-1" {
		t.Errorf("slowestRegion wrong: %+v", r.Summary.SlowestRegion)
	}
}

// TestNilRunMetricsIsSafe confirms every method no-ops on a nil receiver so the
// pipeline can run without --metrics without branching.
func TestNilRunMetricsIsSafe(t *testing.T) {
	var m *RunMetrics
	m.Stage("Collect", 5)
	m.Advance(1)
	m.Log("x")
	m.SetCollectUnits(5)
	m.SetAPIReport(apireq.Report{})
	m.RecordBootstrap("a", "p", 1, time.Second)
	m.RecordService("a", "ec2", time.Second, nil)
	m.RecordRegion("a", "ec2", "us-east-1", time.Second)
	m.Finish(1, 1, 2)
	if err := m.WriteJSON(filepath.Join(t.TempDir(), "x.json")); err != nil {
		t.Fatalf("nil WriteJSON: %v", err)
	}
	m.Stop()
}

func TestAPIReportInJSONAndSummary(t *testing.T) {
	m := New(Environment{})
	m.SetAPIReport(apireq.Report{
		Limits: apireq.Limits{
			MaxRequests:          20_000,
			MaxRequestsPerMinute: 600,
		},
		LogicalCalls:       1_000,
		AttemptsSent:       1_123,
		Retries:            123,
		Successes:          995,
		Failures:           5,
		APIErrors:          17,
		TransportErrors:    3,
		Throttles:          9,
		LimiterWaitMillis:  2_500,
		AttemptMillisTotal: 12_345,
		AttemptMillisMax:   80,
		LimitExceeded:      true,
		Services: []apireq.ServiceReport{
			{
				Name:               "sts",
				LogicalCalls:       1,
				AttemptsSent:       1,
				AttemptMillisTotal: 20,
				AttemptMillisMax:   20,
			},
			{
				Name:               "ec2",
				LogicalCalls:       100,
				AttemptsSent:       110,
				Retries:            10,
				Failures:           5,
				APIErrors:          4,
				TransportErrors:    1,
				Throttles:          3,
				AttemptMillisTotal: 330,
				AttemptMillisMax:   25,
				Operations: []apireq.OperationReport{
					{Name: "DescribeInstances", LogicalCalls: 72, AttemptsSent: 80, Retries: 8, Failures: 4, APIErrors: 4, Throttles: 3, AttemptMillisTotal: 240, AttemptMillisMax: 25},
					{Name: "DescribeRegions", LogicalCalls: 28, AttemptsSent: 30, Retries: 2, Failures: 1, TransportErrors: 1, AttemptMillisTotal: 90, AttemptMillisMax: 10},
				},
			},
		},
	})

	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := m.WriteJSON(path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var written struct {
		AWSApi *apireq.Report `json:"awsApi"`
	}
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if written.AWSApi == nil {
		t.Fatal("awsApi missing from metrics JSON")
	}
	if written.AWSApi.AttemptsSent != 1_123 || len(written.AWSApi.Services) != 2 {
		t.Fatalf("awsApi report not preserved: %+v", written.AWSApi)
	}
	if written.AWSApi.Limits.MaxRequests != 20_000 || written.AWSApi.Limits.MaxRequestsPerMinute != 600 {
		t.Errorf("awsApi limits not preserved: %+v", written.AWSApi.Limits)
	}

	summary := m.Summary()
	for _, want := range []string{
		"AWS API REQUESTS",
		"attempts sent", "1,123",
		"total request limit", "1,123/20,000",
		"requests/minute limit", "600",
		"request limit exceeded", "yes",
		"Service / operation", "Calls", "Attempts", "Retries", "Failed", "Throttles", "Errors", "Avg HTTP", "Max HTTP",
		"ec2", "DescribeInstances", "72", "80", "8", "3", "4", "3.0ms", "25ms",
		"sts",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}
	if strings.Index(summary, "\n  ec2") > strings.Index(summary, "\n  sts") {
		t.Errorf("services are not stably sorted:\n%s", summary)
	}
}

func TestAPIReportOmittedWhenNotSet(t *testing.T) {
	m := New(Environment{})
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := m.WriteJSON(path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"awsApi"`) {
		t.Errorf("offline metrics unexpectedly contain awsApi: %s", raw)
	}
	if strings.Contains(m.Summary(), "AWS API REQUESTS") {
		t.Errorf("offline summary unexpectedly contains API section")
	}
}
