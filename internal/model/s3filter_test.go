package model

import "testing"

func TestS3FilterDefaultConfigExcludesEverything(t *testing.T) {
	// The canonical configs/s3-filter.default.json: default=exclude with ONLY
	// exclude bucket-rules. By first-match-wins semantics a bucket matching no rule
	// still falls to the exclude default, so EVERY bucket (and object) is excluded —
	// the deliberate awshound default that keeps S3 off unless a whitelist is
	// supplied. awshound must reproduce this to match the Python graph.
	cfg := &S3FilterConfig{def: "exclude", rules: []s3FilterRule{
		{action: "exclude", target: "bucket", op: "contains", pattern: "cloudtrail"},
		{action: "exclude", target: "bucket", op: "glob", pattern: "aws-athena-query-results-*"},
	}}
	for _, name := range []string{"my-cloudtrail-logs", "aws-athena-query-results-123", "app-data"} {
		if cfg.ShouldIncludeBucket(name) {
			t.Errorf("bucket %q should be excluded (default=exclude blacklist)", name)
		}
	}
	if cfg.ShouldIncludeObject("anything.txt") {
		t.Error("with default=exclude and no object rule, every object must be excluded")
	}
	d := &S3Data{Buckets: []S3Bucket{
		{Name: "app-data", Objects: []S3Object{{Key: "a"}}},
		{Name: "my-cloudtrail-logs", Objects: []S3Object{{Key: "c"}}},
	}}
	if got := cfg.FilterS3Data(d); len(got.Buckets) != 0 {
		t.Fatalf("default filter must drop all buckets, got %d", len(got.Buckets))
	}
}

func TestS3FilterWhitelistBucketsKeepObjectsExcluded(t *testing.T) {
	// A whitelist: default=exclude but include normal buckets, while objects stay
	// excluded (no object rule) — the shape that keeps bucket nodes without the
	// object-scan explosion.
	cfg := &S3FilterConfig{def: "exclude", rules: []s3FilterRule{
		{action: "exclude", target: "bucket", op: "contains", pattern: "cloudtrail"},
		{action: "include", target: "bucket", op: "glob", pattern: "*"},
	}}
	if !cfg.ShouldIncludeBucket("app-data") {
		t.Error("app-data should be included by the trailing include-* rule")
	}
	if cfg.ShouldIncludeBucket("x-cloudtrail") {
		t.Error("cloudtrail bucket excluded by the earlier first-match rule")
	}
	d := &S3Data{Buckets: []S3Bucket{{Name: "app-data", Objects: []S3Object{{Key: "a"}, {Key: "b"}}}}}
	got := cfg.FilterS3Data(d)
	if len(got.Buckets) != 1 || len(got.Buckets[0].Objects) != 0 {
		t.Fatalf("expected 1 bucket with 0 objects, got %+v", got.Buckets)
	}
}

func TestS3FilterFirstMatchWinsAndOps(t *testing.T) {
	cfg := &S3FilterConfig{def: "exclude", rules: []s3FilterRule{
		{action: "include", target: "object", op: "endswith", pattern: ".tf"},
		{action: "include", target: "object", op: "startswith", pattern: "prod/"},
		{action: "exclude", target: "object", op: "contains", pattern: "secret"},
		{action: "include", target: "object", op: "glob", pattern: "data/*/raw"},
	}}
	cases := map[string]bool{
		"main.tf":       true,  // endswith
		"prod/app.json": true,  // startswith
		"secret.tf":     true,  // first match (.tf) wins over later exclude
		"data/x/raw":    true,  // glob (matches across '/')
		"data/raw":      false, // glob needs a middle segment
		"random.txt":    false, // default exclude
	}
	for key, want := range cases {
		if got := cfg.ShouldIncludeObject(key); got != want {
			t.Errorf("ShouldIncludeObject(%q)=%v want %v", key, got, want)
		}
	}
}

func TestS3FilterNilIsPassthrough(t *testing.T) {
	var cfg *S3FilterConfig
	d := &S3Data{Buckets: []S3Bucket{{Name: "x", Objects: []S3Object{{Key: "y"}}}}}
	if got := cfg.FilterS3Data(d); got != d {
		t.Error("nil filter must return data unchanged")
	}
}

func TestS3FilterCapsObjectsDuringOfflineIngest(t *testing.T) {
	max := 2
	cfg := &S3FilterConfig{def: "include", maxObjectsPerBkt: &max}
	d := &S3Data{Buckets: []S3Bucket{{Name: "x", Objects: []S3Object{
		{Key: "a"}, {Key: "b"}, {Key: "c"},
	}}}}
	got := cfg.FilterS3Data(d)
	if len(got.Buckets) != 1 || len(got.Buckets[0].Objects) != max {
		t.Fatalf("offline object cap not applied: %+v", got.Buckets)
	}
}
