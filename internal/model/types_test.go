package model

import "testing"

func TestKeepDefaultVersionOnly(t *testing.T) {
	p := PolicyDetail{
		DefaultVersionId: "v2",
		PolicyVersions: []PolicyVersion{
			{VersionId: "v1", Document: "old"},
			{VersionId: "v2", Document: "default-by-id"},
			// Preserve an IsDefaultVersion entry too. The downstream node builder
			// keys on this flag while DefaultPolicyDocument also accepts the id.
			{VersionId: "v3", IsDefaultVersion: true, Document: "default-by-flag"},
			{VersionId: "v4", Document: "also-old"},
		},
	}

	p.KeepDefaultVersionOnly()

	if len(p.PolicyVersions) != 2 {
		t.Fatalf("kept %d versions, want the two default candidates", len(p.PolicyVersions))
	}
	if got := p.PolicyVersions[0].VersionId; got != "v2" {
		t.Errorf("first kept version = %q, want v2", got)
	}
	if got := p.PolicyVersions[1].VersionId; got != "v3" {
		t.Errorf("second kept version = %q, want v3", got)
	}
	if got := p.DefaultPolicyDocument(); got != "default-by-id" {
		t.Errorf("DefaultPolicyDocument = %q, want default-by-id", got)
	}
}

func TestKeepDefaultVersionOnlyWithoutDefaultDropsAll(t *testing.T) {
	p := PolicyDetail{PolicyVersions: []PolicyVersion{{VersionId: "v1", Document: "unused"}}}
	p.KeepDefaultVersionOnly()
	if len(p.PolicyVersions) != 0 {
		t.Fatalf("kept %d versions without a default, want 0", len(p.PolicyVersions))
	}
}
