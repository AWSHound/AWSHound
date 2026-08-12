package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/AWSHound/AWSHound/internal/emit"
	"github.com/AWSHound/AWSHound/internal/progress"
	"github.com/AWSHound/AWSHound/internal/runtime"
)

// cmdEmit reads an intermediate built JSON or ZIP and writes the final OpenGraph
// JSON into a ZIP, applying terminal id encoding and the graph/metadata envelope.
func cmdEmit(args []string) {
	fs := flag.NewFlagSet("emit", flag.ExitOnError)
	var (
		in, out, metricsOut string
		verbose             bool
	)
	fs.StringVar(&in, "i", "built.json", "input built-graph path")
	fs.StringVar(&in, "input", "built.json", "input built-graph path (alias of -i)")
	fs.StringVar(&out, "o", "graph.zip", "output OpenGraph ZIP archive path (.zip appended if omitted)")
	fs.StringVar(&out, "output", "graph.zip", "output OpenGraph ZIP archive path (alias of -o; .zip appended if omitted)")
	fs.StringVar(&metricsOut, "metrics", "", "write run metrics JSON to this path")
	fs.BoolVar(&verbose, "v", false, "print detailed current-work logging instead of the progress bar")
	fs.BoolVar(&verbose, "verbose", false, "print detailed current-work logging instead of the progress bar (alias of -v)")
	setGroupedUsage(fs,
		"awshound emit — encode a built graph as OpenGraph JSON.\n\n"+
			"usage:\n"+
			"  awshound emit -i <built.json> -o <graph.json> [flags]",
		"",
		[]flagGroup{
			{"Input", []string{"i"}},
			{"Output", []string{"o", "metrics"}},
			{"Logging", []string{"v"}},
		})
	_ = fs.Parse(args)
	out = runtime.ZIPOutputPath(out, "graph.zip")

	reporter, m := makeReporter(verbose, metricsOut, offlineEnv(nil))
	defer reporter.Stop()

	reporter.Stage("Emit", 0)
	if detailer, ok := reporter.(progress.Detailer); ok {
		detailer.Detail("encoding %s as OpenGraph output %s", in, out)
	}
	f, err := runtime.OpenJSONArtifact(in)
	if err != nil {
		fatal(err)
	}
	var nodeCount, edgeCount int
	if err := runtime.WriteZIP(out, runtime.GraphArtifactName, func(w io.Writer) error {
		var err error
		nodeCount, edgeCount, err = emit.StreamGraphFromBuiltCounted(f, w)
		return err
	}); err != nil {
		f.Close()
		fatal(err)
	}
	if err := f.Close(); err != nil {
		fatal(fmt.Errorf("read %s: %w", in, err))
	}

	reporter.Stop()
	if metricsOut != "" {
		m.Finish(0, nodeCount, edgeCount)
		if err := m.WriteJSON(metricsOut); err != nil {
			fatal(err)
		}
	}

	fmt.Printf("wrote %s: %d nodes, %d edges\n", out, nodeCount, edgeCount)
}
