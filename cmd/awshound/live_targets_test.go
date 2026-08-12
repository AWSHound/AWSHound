package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWithoutCollector(t *testing.T) {
	got := withoutCollector([]string{"iam", "organizations", "s3"}, "organizations")
	want := []string{"iam", "s3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("withoutCollector = %v, want %v", got, want)
	}
	// Absent target is a no-op.
	got = withoutCollector([]string{"iam", "s3"}, "organizations")
	if !reflect.DeepEqual(got, []string{"iam", "s3"}) {
		t.Errorf("withoutCollector(absent) = %v, want [iam s3]", got)
	}
}

func TestSelectProfiles(t *testing.T) {
	// Explicit only, deduped, order preserved.
	if got := selectProfiles([]string{"a", "b", "a"}, ""); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("explicit-only = %v, want [a b]", got)
	}

	// Merge explicit with --aws-config bloodhound_collect profiles: explicit first,
	// config profiles appended, duplicates dropped.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	body := "[profile prod]\nregion = us-east-1\nbloodhound_collect = true\n\n" +
		"[profile staging]\nbloodhound_collect = true\n\n" +
		"[profile ignored]\nregion = us-west-2\n"
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := selectProfiles([]string{"prod", "extra"}, cfg)
	want := []string{"prod", "extra", "staging"} // prod deduped; ignored has no opt-in
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %v, want %v", got, want)
	}
}
