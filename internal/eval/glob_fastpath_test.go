package eval

import "testing"

// TestCompiledGlobMatchesGeneral asserts the fast-path classification in
// compileGlobCached/compiledGlob.match is byte-for-byte equivalent to the general
// rune matcher it replaced (matchActionGlob over compileActionGlob), across
// literal / prefix / suffix / "*" / character-class / interior-star patterns.
func TestCompiledGlobMatchesGeneral(t *testing.T) {
	patterns := []string{
		"", "*", "**", "?", "a", "abc", "s3:GetObject",
		"s3:Get*", "s3:*", "iam:Get*", "*Object", "*", "a*b", "a*b*c",
		"arn:aws:iam::123:role/*", "arn:aws:iam::123:role/Admin",
		"*admin*", "pre?ix", "[abc]def", "[!x]yz", "a[0-9]b", "trail*",
		"*", "]", "[", "a]b", "a-b", "co?tains", "セ*", "*ション",
	}
	names := []string{
		"", "a", "abc", "abd", "s3:GetObject", "s3:PutObject", "s3:Get",
		"iam:GetUser", "MyObject", "arn:aws:iam::123:role/AdminRole",
		"arn:aws:iam::123:role/Admin", "xyz", "yyz", "a5b", "aXb",
		"trailing", "trail", "prefix", "preXix", "adef", "]", "[", "a]b",
		"a-b", "contains", "セクション", "アクション",
	}
	for _, p := range patterns {
		cg := compileGlobCached(p)
		toks := compileActionGlob([]rune(p))
		for _, n := range names {
			got := cg.match(n)
			want := matchActionGlob([]rune(n), toks)
			if got != want {
				t.Errorf("pattern %q name %q: fast-path=%v general=%v (kind=%d)", p, n, got, want, cg.kind)
			}
		}
	}
}
