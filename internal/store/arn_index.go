package store

import (
	"regexp"
	"strings"
	"sync"

	"github.com/RoaringBitmap/roaring/v2"
)

// ArnIndex maps ARNs to dense uint32 ids and back, and resolves ARN wildcard
// patterns to roaring bitmaps of matching ids. This is the primitive the policy
// evaluator uses for set algebra — the in-memory equivalent of AWSHound's
// core/models/arn_index.py ArnUniverseIndex (pyroaring → RoaringBitmap/roaring).
type ArnIndex struct {
	mu           sync.RWMutex
	toInt        map[string]uint32
	toArn        []string
	patternCache map[string]*roaring.Bitmap
	byType       map[string]*roaring.Bitmap
}

// NewArnIndex returns an empty index.
func NewArnIndex() *ArnIndex {
	return &ArnIndex{
		toInt:        make(map[string]uint32),
		patternCache: make(map[string]*roaring.Bitmap),
		byType:       make(map[string]*roaring.Bitmap),
	}
}

// Intern returns the id for arn, assigning a new one if unseen. Adding a new ARN
// invalidates the pattern cache (patterns may now match more ids). Interning
// happens during ingest, before evaluation queries the cache.
func (x *ArnIndex) Intern(arn string) uint32 {
	x.mu.Lock()
	defer x.mu.Unlock()
	if id, ok := x.toInt[arn]; ok {
		return id
	}
	id := uint32(len(x.toArn))
	x.toInt[arn] = id
	x.toArn = append(x.toArn, arn)
	if t := ResourceType(arn); t != "" {
		bm := x.byType[t]
		if bm == nil {
			bm = roaring.New()
			x.byType[t] = bm
		}
		bm.Add(id)
	}
	if len(x.patternCache) > 0 {
		x.patternCache = make(map[string]*roaring.Bitmap)
	}
	return id
}

// TypeBitmap returns a fresh bitmap of the ids of every interned ARN whose
// resource type equals t (see ResourceType). The returned bitmap is a copy the
// caller may mutate; an unknown type yields an empty bitmap.
func (x *ArnIndex) TypeBitmap(t string) *roaring.Bitmap {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if bm, ok := x.byType[t]; ok {
		return bm.Clone()
	}
	return roaring.New()
}

// ID returns the id for arn, if interned.
func (x *ArnIndex) ID(arn string) (uint32, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	id, ok := x.toInt[arn]
	return id, ok
}

// Arn returns the ARN for an id (empty string if out of range).
func (x *ArnIndex) Arn(id uint32) string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if int(id) < len(x.toArn) {
		return x.toArn[id]
	}
	return ""
}

// Size returns the number of interned ARNs.
func (x *ArnIndex) Size() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.toArn)
}

// ResolvePattern returns the bitmap of interned-ARN ids matching an AWS resource
// pattern (IAM wildcards: "*" = any sequence, "?" = any single char). Results
// are memoized. "*" alone matches the entire universe.
func (x *ArnIndex) ResolvePattern(pattern string) *roaring.Bitmap {
	x.mu.RLock()
	if bm, ok := x.patternCache[pattern]; ok {
		x.mu.RUnlock()
		return bm.Clone()
	}
	x.mu.RUnlock()

	bm := roaring.New()
	if pattern == "*" {
		x.mu.RLock()
		for i := range x.toArn {
			bm.Add(uint32(i))
		}
		x.mu.RUnlock()
	} else if !strings.ContainsAny(pattern, "*?") {
		// Exact ARN — a single point lookup.
		if id, ok := x.ID(pattern); ok {
			bm.Add(id)
		}
	} else {
		var match func(string) bool
		if strings.Count(pattern, "*") == 1 && !strings.ContainsRune(pattern, '?') && pattern[len(pattern)-1] == '*' {
			prefix := pattern[:len(pattern)-1]
			match = func(arn string) bool { return strings.HasPrefix(arn, prefix) }
		} else if strings.Count(pattern, "*") == 1 && !strings.ContainsRune(pattern, '?') && pattern[0] == '*' {
			suffix := pattern[1:]
			match = func(arn string) bool { return strings.HasSuffix(arn, suffix) }
		} else {
			re := compileArnPattern(pattern)
			match = re.MatchString
		}
		x.mu.RLock()
		for i, arn := range x.toArn {
			if match(arn) {
				bm.Add(uint32(i))
			}
		}
		x.mu.RUnlock()
	}

	x.mu.Lock()
	x.patternCache[pattern] = bm
	x.mu.Unlock()
	return bm.Clone()
}

// compileArnPattern converts an AWS wildcard pattern to an anchored regexp,
// escaping regex metacharacters and mapping "*"→".*", "?"→".".
func compileArnPattern(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	// Every branch above writes either a regex metacharacter we control (".*" / ".")
	// or QuoteMeta output, so the assembled pattern always compiles — MustCompile
	// never panics here.
	return regexp.MustCompile(b.String())
}
