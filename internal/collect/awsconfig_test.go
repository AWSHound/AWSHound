package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfilesToCollect(t *testing.T) {
	const cfg = `
# a comment
[default]
region = us-east-1
bloodhound_collect = true

[profile prod]
region = us-west-2
role_arn = arn:aws:iam::111122223333:role/audit
bloodhound_collect = true

[profile dev]
region = us-east-1
bloodhound_collect = false

[profile staging]
region = eu-west-1
; no bloodhound_collect key -> skipped

[profile security]
bloodhound_collect = yes
`
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ProfilesToCollect(path)
	if err != nil {
		t.Fatalf("ProfilesToCollect: %v", err)
	}
	want := []string{"default", "prod", "security"} // dev=false, staging=absent excluded
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("profile[%d] = %q, want %q (order/selection wrong): %v", i, got[i], w, got)
		}
	}
}

func TestProfilesToCollectMissingFile(t *testing.T) {
	if _, err := ProfilesToCollect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestParseSectionName(t *testing.T) {
	cases := map[string]string{
		"[default]":          "default",
		"[profile prod]":     "prod",
		"[profile  spaced ]": "spaced",
		"[bare]":             "bare",
	}
	for header, want := range cases {
		if got := parseSectionName(header); got != want {
			t.Errorf("parseSectionName(%q) = %q, want %q", header, got, want)
		}
	}
}
