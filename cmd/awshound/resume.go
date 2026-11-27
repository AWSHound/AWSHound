package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AWSHound/AWSHound/internal/ingest"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/store"
)

// planResume folds an existing raw directory into a live run so only the
// (account, service) units that are missing from disk are collected. For every
// bootstrapped account it checks, per selected collector, whether
// <rawDir>/<account>/<service>.json is already present as a valid, non-empty
// payload; each such unit is dropped from that account's collector list, so the
// subsequent collect only fetches what is missing. When st is non-nil (the `all`
// path, which builds a graph), each present unit is also ingested into st from disk,
// so the final graph is the union of on-disk and freshly collected data; `collect`
// passes a nil st and only needs the skip, since the on-disk files are its output.
//
// Correctness (issue #16): the expected unit set is driven by the run's
// (accounts × collectors) matrix — the bootstrapped accounts and their resolved
// collector lists — NOT by whatever directories happen to exist on disk. An account
// interrupted after N of M services has a directory that is indistinguishable, by
// listing alone, from one fully collected under a smaller --collectors set; diffing
// the intended matrix against files on disk is what lets a partially-collected
// account resume at per-service granularity without silently dropping the services
// it never reached. A unit counts as already-collected only when its file exists and
// ingest.File accepts it (non-empty, parses, recognized shape) — a missing, empty,
// truncated, or unrecognized file re-fetches. Because writeRawFile is atomic
// (tmp+rename), a present file is a trustworthy completion signal.
//
// Known limitation (issue #16, gap 3): a few collectors swallow per-item failures
// (e.g. one AccessDenied bucket policy) and still return a valid, complete-looking
// payload. Such a file has holes that file-existence cannot see, so resume inherits
// them; only a fresh full collection heals them. Resume trades that for not
// re-collecting everything after an interruption.
//
// It mutates boots[i].collectors in place and returns the sorted set of services
// resumed from disk, for the run's reported collector union.
func planResume(boots []bootedSession, rawDir string, st *store.Store, s3Filter *model.S3FilterConfig, reporter progress.Reporter, verbose bool) []string {
	planned := 0
	for _, b := range boots {
		planned += len(b.collectors)
	}
	reporter.Stage("Resume", planned)

	resumed := map[string]bool{}
	onDisk, toCollect := 0, 0
	for i := range boots {
		var todo []string
		for _, svc := range boots[i].collectors {
			reporter.Advance(1)
			path := filepath.Join(rawDir, boots[i].accountID, svc+".json")
			if resumeUnit(st, path, svc, s3Filter) {
				resumed[svc] = true
				onDisk++
				if verbose {
					reporter.Log(fmt.Sprintf("resume: %s/%s.json present, skipping fetch", boots[i].accountID, svc))
				}
				continue
			}
			todo = append(todo, svc)
			toCollect++
		}
		boots[i].collectors = todo
	}
	reporter.Log(fmt.Sprintf("resume: %d unit(s) already on disk, %d to collect", onDisk, toCollect))
	return sortedKeys(resumed)
}

// resumeUnit reports whether <account>/<service>.json is a completed unit that can
// be skipped. When st is non-nil it ingests the file (that full parse is also its
// validity check); when st is nil (collect) it validates without ingesting. It
// returns false (re-fetch) for a missing, empty, or truncated/unparseable file,
// and — defensively — for a file whose content classifies as a different service
// than its name claims (a sign of a hand-corrupted raw tree), so a real slot is
// never left unfilled by a mislabeled payload. Live collection writes unfiltered
// raw JSON on disk while s3Filter bounds what enters st, matching both fresh live
// `all` runs and offline `--input-dir`/`process` runs.
func resumeUnit(st *store.Store, path, expected string, s3Filter *model.S3FilterConfig) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false
	}
	var svc string
	if st != nil {
		svc, err = ingest.File(st, path, s3Filter)
	} else {
		svc, err = ingest.ClassifyFile(path)
	}
	if err != nil {
		return false
	}
	return svc == expected
}
