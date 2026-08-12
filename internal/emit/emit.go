// Package emit serializes an in-memory graph to the BloodHound OpenGraph JSON
// artifact the integration validator consumes:
//
//	{"graph":{"nodes":[...],"edges":[...]},"metadata":{"source_kind":"AWS"}}
//
// Node ids and edge endpoints are colon->underscore encoded at this terminal step
// (graph.EncodeID). WriteGraph takes the fully-built in-memory []*graph.Node /
// []*graph.Edge slices (already deduped upstream in build/edges) and writes them
// incrementally through a buffered writer, so the artifact is serialized without
// ever materializing the whole graph as one string.
package emit

import (
	"bufio"
	"io"

	"github.com/AWSHound/AWSHound/internal/graph"
)

// SourceKind is the OpenGraph metadata.source_kind for this extension.
const SourceKind = "AWS"

// WriteGraph streams the consolidated OpenGraph JSON envelope to w.
func WriteGraph(w io.Writer, nodes []*graph.Node, edges []*graph.Edge) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString(`{"graph":{"nodes":[`); err != nil {
		return err
	}
	for i, n := range nodes {
		if i > 0 {
			if err := bw.WriteByte(','); err != nil {
				return err
			}
		}
		enc := *n
		enc.ID = graph.EncodeID(n.ID)
		b, err := enc.MarshalJSON()
		if err != nil {
			return err
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString(`],"edges":[`); err != nil {
		return err
	}
	for i, e := range edges {
		if i > 0 {
			if err := bw.WriteByte(','); err != nil {
				return err
			}
		}
		enc := *e
		enc.Start = graph.EncodeID(e.Start)
		enc.End = graph.EncodeID(e.End)
		b, err := enc.MarshalJSON()
		if err != nil {
			return err
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
	}
	// `]}` closes the edges array AND the "graph" object; metadata is its sibling.
	if _, err := bw.WriteString(`]},"metadata":{"source_kind":"` + SourceKind + `"}}`); err != nil {
		return err
	}
	return bw.Flush()
}
