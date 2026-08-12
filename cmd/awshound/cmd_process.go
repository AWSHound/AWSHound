package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/AWSHound/AWSHound/internal/runtime"
	"github.com/AWSHound/AWSHound/internal/store"
)

// cmdProcess builds the graph from previously collected data and streams the
// intermediate built.json (nodes/edges with raw ARN ids) into a ZIP archive.
// Input is a raw collect directory (--input-dir) or a single GAAD file (--gaad).
func cmdProcess(args []string) {
	fs := flag.NewFlagSet("process", flag.ExitOnError)
	var (
		inputDir, gaadPath, out, metricsOut, s3Filter string
		verbose                                       bool
	)
	fs.StringVar(&inputDir, "input-dir", "", "directory of raw collect JSON to build from")
	fs.StringVar(&gaadPath, "gaad", "", "single GAAD JSON file to build from")
	fs.StringVar(&out, "o", "built.zip", "output ZIP archive path (.zip appended if omitted)")
	fs.StringVar(&out, "output", "built.zip", "output ZIP archive path (alias of -o; .zip appended if omitted)")
	fs.StringVar(&s3Filter, "s3-filter", "", "path to S3 filter config; include/exclude buckets and objects (default: process all)")
	fs.StringVar(&metricsOut, "metrics", "", "write run metrics JSON to this path")
	fs.BoolVar(&verbose, "v", false, "print detailed current-work logging instead of the progress bar")
	fs.BoolVar(&verbose, "verbose", false, "print detailed current-work logging instead of the progress bar (alias of -v)")
	setGroupedUsage(fs,
		"awshound process — build the graph from collected JSON.\n\n"+
			"usage:\n"+
			"  awshound process --input-dir <dir> [flags]\n"+
			"  awshound process --gaad <file>     [flags]",
		"",
		[]flagGroup{
			{"Source (choose one)", []string{"input-dir", "gaad"}},
			{"Filtering", []string{"s3-filter"}},
			{"Output", []string{"o", "metrics"}},
			{"Logging", []string{"v"}},
		})
	_ = fs.Parse(args)

	if (inputDir == "") == (gaadPath == "") {
		fmt.Fprintln(os.Stderr, "process: exactly one of --input-dir or --gaad is required")
		os.Exit(2)
	}
	out = runtime.ZIPOutputPath(out, "built.zip")

	s := store.New()
	reporter, m := makeReporter(verbose, metricsOut, offlineEnv(nil))
	defer reporter.Stop()

	if inputDir != "" {
		m.SetCollectors(ingestDir(s, inputDir, reporter, verbose, loadS3Filter(s3Filter)))
	} else {
		acct := ingestGAADFile(s, gaadPath)
		m.SetCollectors([]string{"iam"})
		if verbose {
			reporter.Log(fmt.Sprintf("ingested GAAD for account %s", acct))
		}
	}

	// Stream nodes straight to built.json so the volume-scaling node set never
	// accumulates in memory (§9 of docs/authorization-tensor.md). Output is
	// byte-identical to the accumulate-then-write path.
	var nodeCount, edgeCount int
	if err := runtime.WriteZIP(out, runtime.BuiltArtifactName, func(w io.Writer) (err error) {
		nodeCount, edgeCount, err = runtime.StreamBuildToBuilt(s, w, reporter, m)
		return err
	}); err != nil {
		fatal(err)
	}

	reporter.Stop()
	if metricsOut != "" {
		m.Finish(len(s.Accounts()), nodeCount, edgeCount)
		if err := m.WriteJSON(metricsOut); err != nil {
			fatal(err)
		}
		fmt.Fprint(os.Stderr, m.Summary())
	}

	fmt.Printf("wrote %s: %d nodes, %d edges (%d account(s))\n",
		out, nodeCount, edgeCount, len(s.Accounts()))
}
