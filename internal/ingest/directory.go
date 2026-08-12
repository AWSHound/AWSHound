// Package ingest loads a directory of pre-fetched AWS collect JSON into the
// store. It is the Go port of AWSHound's core/ingestion/input_dir.py: point
// --input-dir at a tree of *.json files — flat, or organized as
// <account>/<service>.json, or any layout — and each file is classified by its
// content (a distinctive top-level key) rather than its name and routed to the
// matching store ingest. Filenames and directory structure are ignored for
// routing, so no per-service flags or naming convention is required.
//
// The account id for a file comes from the payload itself (a service's AccountId
// field, or the principal ARNs of a GAAD document, or an Organizations
// MasterAccountId). When a payload carries no account id, a 12-digit path
// component is used as a fallback, so a tree organized by account id still lands
// each file under the right account.
package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/runtime"
	"github.com/AWSHound/AWSHound/internal/store"
)

// discriminators map a distinctive top-level JSON key to the service that owns
// that shape. Classification stops at the first recognized key. No collect
// payload carries more than one of these, so ordering is not significant.
var discriminators = map[string]string{
	"SCPPolicies":             "organizations",
	"RCPPolicies":             "organizations",
	"Organization":            "organizations",
	"RoleDetailList":          "iam",
	"UserDetailList":          "iam",
	"GroupDetailList":         "iam",
	"Buckets":                 "s3",
	"Keys":                    "kms",
	"Functions":               "lambda",
	"Parameters":              "ssm",
	"ManagedInstances":        "ssm",
	"Clusters":                "eks",
	"NodeGroups":              "eks",
	"AccessEntries":           "eks",
	"PodIdentityAssociations": "eks",
	"Stacks":                  "cloudformation",
	"Instances":               "ec2",
}

// accountDirRe matches a path component that is a bare 12-digit AWS account id,
// used to attribute a file whose payload lacks an account id.
var accountDirRe = regexp.MustCompile(`^\d{12}$`)

// Result reports what a directory ingest did.
type Result struct {
	Counts  map[string]int // files ingested per service
	Skipped int            // files whose shape was not recognized
	Files   int            // total *.json files found
}

// Services returns the sorted set of services that had at least one file
// ingested — the offline analogue of the collectors that "ran".
func (r Result) Services() []string {
	out := make([]string, 0, len(r.Counts))
	for svc := range r.Counts {
		out = append(out, svc)
	}
	sort.Strings(out)
	return out
}

// Directory recursively ingests every *.json file under dir into st, reporting an
// "Ingest" stage that advances per file. Files are parsed and ingested
// concurrently (the store is safe for concurrent use); a read/parse/ingest
// failure aborts loudly rather than being silently skipped. Unrecognized files
// are counted as skipped, not errors.
func Directory(st *store.Store, dir string, reporter progress.Reporter, s3Filter *model.S3FilterConfig) (Result, error) {
	files, err := findJSON(dir)
	if err != nil {
		return Result{}, err
	}
	reporter.Stage("Ingest", len(files))
	if len(files) == 0 {
		reporter.Log(fmt.Sprintf("ingest: no .json files found under %s", dir))
		return Result{Counts: map[string]int{}}, nil
	}

	type outcome struct {
		service string
		err     error
	}
	outcomes := make([]outcome, len(files))
	sem := make(chan struct{}, ingestWorkers(len(files)))
	var wg sync.WaitGroup
	for i, path := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, path string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer reporter.Advance(1)
			if detailer, ok := reporter.(progress.Detailer); ok {
				detailer.Detail("ingesting %s", path)
			}
			svc, err := ingestFile(st, path, s3Filter)
			outcomes[i] = outcome{svc, err}
		}(i, path)
	}
	wg.Wait()

	res := Result{Counts: map[string]int{}, Files: len(files)}
	for i, o := range outcomes {
		switch {
		case o.err != nil:
			// First failure wins; report it with the offending path.
			return res, fmt.Errorf("ingest %s: %w", files[i], o.err)
		case o.service == "":
			res.Skipped++
			reporter.Log(fmt.Sprintf("ingest: skipped %s (unrecognized shape)", files[i]))
		default:
			res.Counts[o.service]++
		}
	}
	return res, nil
}

// File ingests a single collect JSON file into st, classifying it by content
// exactly as Directory does, and returns the service it was routed to ("" when the
// file's shape is unrecognized). It is the single-file entry `all --resume` uses to
// fold an already-collected <account>/<service>.json back into the store without a
// full-directory walk. A read/parse/ingest failure — including a truncated file
// left by an interrupted run — is returned as an error, so the caller can treat
// that unit as not-yet-collected and re-fetch it.
func File(st *store.Store, path string, s3Filter *model.S3FilterConfig) (string, error) {
	return ingestFile(st, path, s3Filter)
}

// ClassifyFile reads path and returns the service its content classifies as ("" if
// the shape is unrecognized), WITHOUT ingesting it into a store. It errors on a read
// failure or a file that is not complete, valid JSON — a truncated payload from an
// interrupted run. It is the store-free completion check `collect --resume` uses
// (collect writes raw JSON but never builds a store), mirroring the validity that
// File's full ingest gives the `all --resume` path.
func ClassifyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// json.Valid catches a truncated file that detectService alone would miss when
	// the discriminator key precedes the truncation (it stops at the first match).
	if !json.Valid(b) {
		return "", fmt.Errorf("invalid or incomplete JSON")
	}
	return detectService(b)
}

// findJSON returns every *.json file under dir, sorted for deterministic output.
func findJSON(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".json" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	sort.Strings(files)
	return files, nil
}

// ingestFile loads, classifies, and ingests one file. It returns the service name
// on success, "" when the file's shape is unrecognized (a legitimate skip, e.g. a
// stray readme.json), or an error on a read/parse/ingest failure.
func ingestFile(st *store.Store, path string, s3Filter *model.S3FilterConfig) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	service, err := detectService(b)
	if err != nil {
		return "", err
	}
	if service == "" {
		return "", nil
	}

	switch service {
	case "iam":
		// GAAD policy documents may arrive as decoded JSON objects or URL-encoded
		// strings; normalize to the model's string form first, exactly as the
		// single-file --gaad path does.
		nb, err := model.NormalizeGAADDocs(b)
		if err != nil {
			return "", err
		}
		var d model.AuthDetails
		if err := json.Unmarshal(nb, &d); err != nil {
			return "", err
		}
		acct := runtime.AccountIDFromGAAD(&d)
		if acct == "" {
			acct = accountFromPath(path)
		}
		if acct == "" {
			return "", fmt.Errorf("iam: could not determine account id")
		}
		st.AddAuthDetails(acct, &d)
	case "organizations":
		var d model.OrganizationsData
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct := d.Organization.MasterAccountId
		if acct == "" {
			acct = accountFromPath(path)
		}
		if acct == "" {
			return "", fmt.Errorf("organizations: could not determine account id")
		}
		store.IngestOrganizations(st, acct, &d)
	case "s3":
		var d model.S3Data
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		// Apply the S3 filter (bucket/object include-exclude) before ingest, exactly
		// as input_dir.py does; a nil filter leaves the data unchanged.
		store.IngestS3(st, acct, s3Filter.FilterS3Data(&d))
	case "kms":
		var d model.KMSData
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		store.IngestKMS(st, acct, &d)
	case "ssm":
		var d model.SSMData
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		store.IngestSSM(st, acct, &d)
	case "lambda":
		var d model.LambdaData
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		store.IngestLambda(st, acct, &d)
	case "cloudformation":
		var d model.CloudFormationData
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		store.IngestCloudFormation(st, acct, &d)
	case "ec2":
		var d model.EC2Data
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		store.IngestEC2(st, acct, &d)
	case "eks":
		var d model.EKSData
		if err := json.Unmarshal(b, &d); err != nil {
			return "", err
		}
		acct, err := accountFor(d.AccountId, path, service)
		if err != nil {
			return "", err
		}
		store.IngestEKS(st, acct, &d)
	default:
		return "", nil
	}
	return service, nil
}

// accountFor resolves the account id for a service payload, falling back to a
// 12-digit path component when the payload's AccountId is empty.
func accountFor(payloadAccount, path, service string) (string, error) {
	if payloadAccount != "" {
		return payloadAccount, nil
	}
	if acct := accountFromPath(path); acct != "" {
		return acct, nil
	}
	return "", fmt.Errorf("%s: payload has no AccountId and no 12-digit account id in path", service)
}

// accountFromPath returns the first path component that is a bare 12-digit AWS
// account id, or "" if none — the fallback for account-id-organized trees.
func accountFromPath(path string) string {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if accountDirRe.MatchString(part) {
			return part
		}
	}
	return ""
}

// detectService scans only the top-level keys of a JSON object and returns the
// service for the first recognized key, or "" if the payload is not an object or
// has no recognized key. It reads with a streaming decoder so a huge document is
// classified without a full second parse.
func detectService(b []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", nil // not a JSON object → unrecognized
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", err
		}
		key, _ := keyTok.(string)
		if svc, ok := discriminators[key]; ok {
			return svc, nil
		}
		if err := skipValue(dec); err != nil {
			return "", err
		}
	}
	return "", nil
}

// skipValue consumes exactly one JSON value (the value following a key) from dec,
// descending into nested objects/arrays until balanced.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

const defaultIngestWorkers = 2

// ingestWorkers bounds how many files parse/ingest concurrently. IAM payloads
// temporarily occupy several times their on-disk size while encoding/json builds
// the full object graph, so a CPU-count default can put a dozen multi-megabyte
// GAAD documents in flight and OOM before AddAuthDetails has a chance to discard
// non-default managed-policy versions. Two workers keeps that transient bounded;
// GOAWSHOUND_INGEST_WORKERS is an operator override for hosts with a different
// memory/throughput tradeoff. Invalid and non-positive values fall back safely.
func ingestWorkers(files int) int {
	w := defaultIngestWorkers
	if v := os.Getenv("GOAWSHOUND_INGEST_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			w = n
		}
	}
	if w > files {
		w = files
	}
	if w < 1 {
		w = 1
	}
	return w
}
