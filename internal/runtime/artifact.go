package runtime

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	BuiltArtifactName = "built.json"
	GraphArtifactName = "graph.json"
)

// ZIPOutputPath converts a requested output file into a ZIP archive path. A
// directory request receives defaultName; a non-.zip file request gets .zip
// appended so existing -o graph.json usage produces graph.json.zip.
func ZIPOutputPath(path, defaultName string) string {
	if path == "" {
		return defaultName
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return filepath.Join(path, defaultName)
	}
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		return filepath.Join(path, defaultName)
	}
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		return path
	}
	return path + ".zip"
}

// WriteZIP streams one JSON member into a ZIP archive without materializing the
// uncompressed artifact on disk. Best-speed DEFLATE substantially reduces large
// repetitive graph JSON while keeping the long-running build CPU-oriented.
func WriteZIP(path, member string, write func(io.Writer) error) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestSpeed)
	})
	h := &zip.FileHeader{Name: member, Method: zip.Deflate}
	w, err := zw.CreateHeader(h)
	if err == nil {
		err = write(w)
	}
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// OpenJSONArtifact opens a raw JSON file or the first JSON member in a ZIP.
// The returned reader owns all underlying descriptors and must be closed.
func OpenJSONArtifact(path string) (io.ReadCloser, error) {
	if !strings.EqualFold(filepath.Ext(path), ".zip") {
		return os.Open(path)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	var member *zip.File
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && strings.EqualFold(filepath.Ext(f.Name), ".json") {
			member = f
			break
		}
	}
	if member == nil {
		zr.Close()
		return nil, fmt.Errorf("%s: archive contains no JSON member", path)
	}
	r, err := member.Open()
	if err != nil {
		zr.Close()
		return nil, err
	}
	return &zipJSONReader{ReadCloser: r, archive: zr}, nil
}

type zipJSONReader struct {
	io.ReadCloser
	archive *zip.ReadCloser
}

func (r *zipJSONReader) Close() error {
	err := r.ReadCloser.Close()
	if closeErr := r.archive.Close(); err == nil {
		err = closeErr
	}
	return err
}
