package graph

import (
	"bufio"
	"io"
)

// BuiltStreamWriter writes a built graph incrementally — nodes one at a time,
// then edges one at a time — producing bytes identical to WriteBuilt but without
// ever holding the whole node or edge set in memory. It is the sink for the
// streaming build path (build.StreamNodes → Node; AllEdges → Edge), which bounds
// peak memory by the volume-scaling node set (§9 of docs/authorization-tensor.md).
//
// Usage: Node* then Edges() then Edge* then Close(). Edges() must be called once,
// after the last Node and before the first Edge, even when there are no edges.
type BuiltStreamWriter struct {
	bw        *bufio.Writer
	inEdges   bool
	wroteNode bool
	wroteEdge bool
	err       error
}

// NewBuiltStreamWriter starts a built document, writing the {"nodes":[ prefix.
func NewBuiltStreamWriter(w io.Writer) *BuiltStreamWriter {
	bw := bufio.NewWriter(w)
	s := &BuiltStreamWriter{bw: bw}
	_, s.err = bw.WriteString(`{"nodes":[`)
	return s
}

// Node appends one node to the nodes array (raw ARN ids, no encoding).
func (s *BuiltStreamWriter) Node(n *Node) error {
	if s.err != nil {
		return s.err
	}
	if s.inEdges {
		s.err = io.ErrClosedPipe
		return s.err
	}
	if s.wroteNode {
		if s.err = s.bw.WriteByte(','); s.err != nil {
			return s.err
		}
	}
	s.wroteNode = true
	return s.write(n.MarshalJSON())
}

// Edges closes the nodes array and opens the edges array: ],"edges":[.
func (s *BuiltStreamWriter) Edges() error {
	if s.err != nil {
		return s.err
	}
	if s.inEdges {
		return nil
	}
	s.inEdges = true
	_, s.err = s.bw.WriteString(`],"edges":[`)
	return s.err
}

// Edge appends one edge to the edges array.
func (s *BuiltStreamWriter) Edge(e *Edge) error {
	if s.err != nil {
		return s.err
	}
	if !s.inEdges {
		if err := s.Edges(); err != nil {
			return err
		}
	}
	if s.wroteEdge {
		if s.err = s.bw.WriteByte(','); s.err != nil {
			return s.err
		}
	}
	s.wroteEdge = true
	return s.write(e.MarshalJSON())
}

// Close writes the ]} suffix and flushes.
func (s *BuiltStreamWriter) Close() error {
	if s.err != nil {
		return s.err
	}
	if !s.inEdges {
		if err := s.Edges(); err != nil {
			return err
		}
	}
	if _, s.err = s.bw.WriteString(`]}`); s.err != nil {
		return s.err
	}
	s.err = s.bw.Flush()
	return s.err
}

// write appends a pre-marshaled fragment, capturing a marshal error.
func (s *BuiltStreamWriter) write(b []byte, err error) error {
	if err != nil {
		s.err = err
		return err
	}
	_, s.err = s.bw.Write(b)
	return s.err
}
