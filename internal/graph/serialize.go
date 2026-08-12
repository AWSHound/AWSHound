package graph

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// This file adds the inverse of the MarshalJSON methods so a built graph can be
// written to and read back from an intermediate "built.json" artifact — the
// hand-off between the `process` and `emit` subcommands. The intermediate uses
// the same node/edge JSON shape as the final OpenGraph output but with raw ARN
// ids (id encoding stays a terminal concern of the emit package). Round-tripping
// preserves property insertion order and exact numeric text, so re-emitting a
// read-back graph is byte-identical to emitting it directly.

// setRaw appends key=value without the isValidPropertyValue check that Set
// enforces. It is used only by UnmarshalJSON, where values come from a decoder
// (json.Number, []any, string, bool, nil) rather than the model's typed setters,
// and are re-serialized verbatim.
func (p *Properties) setRaw(key string, value any) {
	if p.vals == nil {
		p.vals = make(map[string]any)
	}
	if _, ok := p.vals[key]; !ok {
		p.keys = append(p.keys, key)
	}
	p.vals[key] = value
}

// UnmarshalJSON reads a JSON object into Properties, preserving key order. Numbers
// are decoded as json.Number so large integers keep their exact text on re-emit.
func (p *Properties) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil // JSON null → no properties
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("graph: properties must be a JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("graph: non-string property key %v", keyTok)
		}
		var v any
		if err := dec.Decode(&v); err != nil {
			return err
		}
		p.setRaw(key, v)
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return err
	}
	return nil
}

// UnmarshalJSON reads {"id":...,"kinds":[...],"properties":{...}} into a Node,
// the inverse of Node.MarshalJSON.
func (n *Node) UnmarshalJSON(b []byte) error {
	var aux struct {
		ID    string          `json:"id"`
		Kinds []NodeKind      `json:"kinds"`
		Props json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	n.ID = aux.ID
	n.Kinds = aux.Kinds
	n.Props = NewProperties()
	if len(aux.Props) > 0 {
		if err := n.Props.UnmarshalJSON(aux.Props); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalJSON reads {"kind":...,"start":{"value":...},"end":{"value":...}
// [,"properties":{...}]} into an Edge, the inverse of Edge.MarshalJSON.
func (e *Edge) UnmarshalJSON(b []byte) error {
	var aux struct {
		Kind  EdgeKind `json:"kind"`
		Start struct {
			Value string `json:"value"`
		} `json:"start"`
		End struct {
			Value string `json:"value"`
		} `json:"end"`
		Props json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	e.Kind = aux.Kind
	e.Start = aux.Start.Value
	e.End = aux.End.Value
	e.Props = NewProperties()
	if len(aux.Props) > 0 {
		if err := e.Props.UnmarshalJSON(aux.Props); err != nil {
			return err
		}
	}
	return nil
}

// WriteBuilt streams the built graph to w as {"nodes":[...],"edges":[...]} using
// raw ARN ids (no id encoding, no OpenGraph envelope) — the `process`→`emit`
// hand-off artifact.
func WriteBuilt(w io.Writer, nodes []*Node, edges []*Edge) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString(`{"nodes":[`); err != nil {
		return err
	}
	for i, n := range nodes {
		if i > 0 {
			if err := bw.WriteByte(','); err != nil {
				return err
			}
		}
		b, err := n.MarshalJSON()
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
		b, err := e.MarshalJSON()
		if err != nil {
			return err
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString(`]}`); err != nil {
		return err
	}
	return bw.Flush()
}

// ReadBuilt reads a built.json artifact written by WriteBuilt back into node and
// edge slices, preserving property order.
func ReadBuilt(r io.Reader) ([]*Node, []*Edge, error) {
	var doc struct {
		Nodes []*Node `json:"nodes"`
		Edges []*Edge `json:"edges"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, nil, err
	}
	return doc.Nodes, doc.Edges, nil
}
