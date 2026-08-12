package runtime

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestZIPOutputPath(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		path, defaultName, want string
	}{
		{"graph.json", "graph.zip", "graph.json.zip"},
		{"graph.zip", "graph.zip", "graph.zip"},
		{dir, "graph.zip", filepath.Join(dir, "graph.zip")},
		{filepath.Join(dir, "new") + string(os.PathSeparator), "built.zip", filepath.Join(dir, "new", "built.zip")},
	} {
		if got := ZIPOutputPath(tc.path, tc.defaultName); got != tc.want {
			t.Errorf("ZIPOutputPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestWriteAndOpenZIPArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "built.zip")
	want := `{"nodes":[],"edges":[]}`
	if err := WriteZIP(path, BuiltArtifactName, func(w io.Writer) error {
		_, err := io.WriteString(w, want)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := OpenJSONArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	closeErr := r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if string(got) != want {
		t.Fatalf("archive contents = %q, want %q", got, want)
	}
}
