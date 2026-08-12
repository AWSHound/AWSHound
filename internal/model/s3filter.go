package model

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// S3FilterConfig controls which S3 buckets and objects enter the graph. It is the
// Go port of awshound/core/models/s3_filter.py S3FilterConfig, with byte-identical
// evaluation semantics: first-match-wins over ordered rules, falling back to the
// configured default.
//
// Without a filter awshound processes every collected bucket and object, which
// on real accounts is millions of (object × principal) authorization checks — the
// dominant build cost. The canonical configs/s3-filter.default.json sets
// default="exclude" with only bucket-target rules, so ShouldIncludeObject returns
// false for every object: no S3 object edges are produced, exactly as the Python
// tool does with that filter. See docs and [[awshound-slow-on-policy-heavy-accounts]].
type S3FilterConfig struct {
	def              string // "include" or "exclude"
	maxObjectsPerBkt *int
	rules            []s3FilterRule
}

// s3FilterRule is one ordered include/exclude rule. target is "bucket" or "object";
// op is one of glob/contains/startswith/endswith/exact; pattern is the operand.
type s3FilterRule struct {
	action  string // "include" | "exclude"
	target  string // "bucket" | "object"
	op      string // "glob" | "contains" | "startswith" | "endswith" | "exact"
	pattern string
}

// s3FilterFileFmt mirrors the on-disk JSON shape for decoding + validation.
type s3FilterFileFmt struct {
	Version          *int                         `json:"version"`
	Default          *string                      `json:"default"`
	MaxObjectsPerBkt *int                         `json:"max_objects_per_bucket"`
	Rules            []map[string]json.RawMessage `json:"rules"`
}

// LoadS3Filter reads and validates an S3 filter config from a JSON file. Ported
// from S3FilterConfig.from_file, including its validation errors, so a malformed
// filter is rejected up front rather than silently mis-filtering.
func LoadS3Filter(path string) (*S3FilterConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f s3FilterFileFmt
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("s3 filter: %w", err)
	}
	if f.Version == nil || *f.Version != 1 {
		return nil, fmt.Errorf("s3 filter: unsupported version %v (expected 1)", ptrIntStr(f.Version))
	}
	def := "exclude"
	if f.Default != nil {
		def = *f.Default
	}
	if def != "include" && def != "exclude" {
		return nil, fmt.Errorf("s3 filter: default must be 'include' or 'exclude', got %q", def)
	}
	if f.MaxObjectsPerBkt != nil && *f.MaxObjectsPerBkt < 0 {
		return nil, fmt.Errorf("s3 filter: max_objects_per_bucket must be non-negative, got %d", *f.MaxObjectsPerBkt)
	}
	cfg := &S3FilterConfig{def: def, maxObjectsPerBkt: f.MaxObjectsPerBkt}
	for i, raw := range f.Rules {
		rule, err := parseS3FilterRule(raw, i)
		if err != nil {
			return nil, err
		}
		cfg.rules = append(cfg.rules, rule)
	}
	return cfg, nil
}

// parseS3FilterRule decodes and validates one rule. Ported from _validate_rule:
// the operand key is "name" for a bucket rule and "key" for an object rule, and
// the matcher must be a single-operator dict.
func parseS3FilterRule(raw map[string]json.RawMessage, index int) (s3FilterRule, error) {
	var action, target string
	if err := jsonStr(raw["action"], &action); err != nil || (action != "include" && action != "exclude") {
		return s3FilterRule{}, fmt.Errorf("s3 filter: rule %d: 'action' must be 'include' or 'exclude'", index)
	}
	if err := jsonStr(raw["target"], &target); err != nil || (target != "bucket" && target != "object") {
		return s3FilterRule{}, fmt.Errorf("s3 filter: rule %d: 'target' must be 'bucket' or 'object'", index)
	}
	var match map[string]map[string]string
	if err := json.Unmarshal(raw["match"], &match); err != nil {
		return s3FilterRule{}, fmt.Errorf("s3 filter: rule %d: 'match' must be a dict", index)
	}
	operandKey := "name"
	if target == "object" {
		operandKey = "key"
	}
	matcher, ok := match[operandKey]
	if !ok {
		return s3FilterRule{}, fmt.Errorf("s3 filter: rule %d: 'match' for target %q must contain %q", index, target, operandKey)
	}
	if len(matcher) != 1 {
		return s3FilterRule{}, fmt.Errorf("s3 filter: rule %d: match must have exactly one operator", index)
	}
	var op, pattern string
	for k, v := range matcher {
		op, pattern = k, v
	}
	switch op {
	case "glob", "contains", "startswith", "endswith", "exact":
	default:
		return s3FilterRule{}, fmt.Errorf("s3 filter: rule %d: unknown match operator %q", index, op)
	}
	return s3FilterRule{action: action, target: target, op: op, pattern: pattern}, nil
}

// ShouldIncludeBucket reports whether a bucket is included. Ported from
// should_include_bucket / _evaluate_rules("bucket", name).
func (c *S3FilterConfig) ShouldIncludeBucket(name string) bool {
	return c.evaluate("bucket", name)
}

// ShouldIncludeObject reports whether an object key is included. Ported from
// should_include_object / _evaluate_rules("object", key). The bucket must
// separately pass ShouldIncludeBucket.
func (c *S3FilterConfig) ShouldIncludeObject(key string) bool {
	return c.evaluate("object", key)
}

// evaluate runs the ordered rules for a target type (first match wins), falling
// back to the default. Ported from _evaluate_rules.
func (c *S3FilterConfig) evaluate(target, value string) bool {
	for _, r := range c.rules {
		if r.target != target {
			continue
		}
		if r.matches(value) {
			return r.action == "include"
		}
	}
	return c.def == "include"
}

// matches applies a rule's operator to a value. Ported from _match_rule.
func (r s3FilterRule) matches(value string) bool {
	switch r.op {
	case "glob":
		return fnmatch(value, r.pattern)
	case "contains":
		return strings.Contains(value, r.pattern)
	case "startswith":
		return strings.HasPrefix(value, r.pattern)
	case "endswith":
		return strings.HasSuffix(value, r.pattern)
	case "exact":
		return value == r.pattern
	}
	return false
}

// FilterS3Data returns a filtered copy of the S3 data: excluded buckets are
// dropped, and within each included bucket, excluded objects are removed. Ported
// from S3FilterConfig.filter_s3_data. A nil filter returns the data unchanged.
//
// max_objects_per_bucket also bounds offline re-ingestion. Applying the same
// configured budget to an already-collected directory prevents a raw export from
// silently reintroducing an object × principal authorization explosion.
func (c *S3FilterConfig) FilterS3Data(d *S3Data) *S3Data {
	if c == nil || d == nil {
		return d
	}
	out := &S3Data{AccountId: d.AccountId, AccountPublicAccessBlock: d.AccountPublicAccessBlock}
	for _, b := range d.Buckets {
		if !c.ShouldIncludeBucket(b.Name) {
			continue
		}
		if len(b.Objects) > 0 {
			kept := make([]S3Object, 0, len(b.Objects))
			for _, o := range b.Objects {
				if c.ShouldIncludeObject(o.Key) {
					kept = append(kept, o)
				}
			}
			if c.maxObjectsPerBkt != nil && len(kept) > *c.maxObjectsPerBkt {
				kept = kept[:*c.maxObjectsPerBkt]
			}
			b.Objects = kept
		}
		out.Buckets = append(out.Buckets, b)
	}
	return out
}

// EffectiveMaxObjects returns the per-bucket object cap for live collection: the
// config value when set, else the caller's default. Ported from
// effective_max_objects.
func (c *S3FilterConfig) EffectiveMaxObjects(def int) int {
	if c != nil && c.maxObjectsPerBkt != nil {
		return *c.maxObjectsPerBkt
	}
	return def
}

func ptrIntStr(p *int) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *p)
}

func jsonStr(raw json.RawMessage, dst *string) error {
	if raw == nil {
		return fmt.Errorf("missing")
	}
	return json.Unmarshal(raw, dst)
}
