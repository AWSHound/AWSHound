package collect

import (
	"context"
	"testing"

	"github.com/AWSHound/AWSHound/internal/apireq"
)

// TestNewAssumeRoleSession checks the assume-role session is built from the base
// config template without touching the network (the STS AssumeRole provider is
// lazy — credentials are only fetched on first API use): the region override is
// applied, the base session is left unmutated, and an empty role name is rejected.
func TestNewAssumeRoleSession(t *testing.T) {
	ctx := context.Background()
	base, err := NewSession(ctx, "", "us-east-1")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	child, err := NewAssumeRoleSession(base, "123456789012", "OrganizationAccountAccessRole", "us-west-2")
	if err != nil {
		t.Fatalf("NewAssumeRoleSession: %v", err)
	}
	if child.Region != "us-west-2" {
		t.Errorf("child region = %q, want us-west-2", child.Region)
	}
	if child.Cfg.Credentials == nil {
		t.Error("child config has no credentials provider")
	}
	// The base session is a shared template and must not be mutated.
	if base.Region != "us-east-1" {
		t.Errorf("base region mutated to %q, want us-east-1", base.Region)
	}

	// An empty role name is a programming error, not a silent no-op.
	if _, err := NewAssumeRoleSession(base, "123456789012", "", "us-east-1"); err == nil {
		t.Error("NewAssumeRoleSession with empty role name: want error, got nil")
	}
}

// TestAPIRequestInstrumentationPropagates checks that an optional controller is
// installed once on a new config and survives the config copy used for child
// accounts. NewFromConfig consumes these two config fields for both the base STS
// AssumeRole client and every service client built from the child.
func TestAPIRequestInstrumentationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	controller := apireq.New(apireq.Limits{}, cancel)

	base, err := NewSession(ctx, "", "us-east-1", controller)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if base.Cfg.HTTPClient == sharedHTTPClient {
		t.Error("instrumented session still uses the unwrapped shared HTTP client")
	}
	if got := len(base.Cfg.APIOptions); got != 1 {
		t.Fatalf("base API option count = %d, want 1", got)
	}

	// Reusing a controller for several account targets must reuse the same HTTP
	// wrapper and must not register its middleware more than once per config.
	another, err := NewSession(ctx, "", "us-west-2", controller)
	if err != nil {
		t.Fatalf("second NewSession: %v", err)
	}
	if another.Cfg.HTTPClient != base.Cfg.HTTPClient {
		t.Error("sessions using the same controller did not reuse its HTTP wrapper")
	}
	if got := len(another.Cfg.APIOptions); got != 1 {
		t.Errorf("second session API option count = %d, want 1", got)
	}

	child, err := NewAssumeRoleSession(base, "123456789012", "OrganizationAccountAccessRole", "")
	if err != nil {
		t.Fatalf("NewAssumeRoleSession: %v", err)
	}
	if child.Cfg.HTTPClient != base.Cfg.HTTPClient {
		t.Error("child did not inherit the instrumented HTTP client")
	}
	if got := len(child.Cfg.APIOptions); got != len(base.Cfg.APIOptions) {
		t.Errorf("child API option count = %d, want %d", got, len(base.Cfg.APIOptions))
	}
}
