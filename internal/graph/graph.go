// Package graph defines the BloodHound OpenGraph node/edge model that awshound
// emits. It is a faithful port of AWSHound's core/graph/types.py.
//
// The wire-JSON shape is load-bearing — BHE's OpenGraph ingest and the
// integration validator both key off it:
//
//	node: {"id":<id>,"kinds":[...],"properties":{...}}   // properties ALWAYS present
//	edge: {"kind":<k>,"start":{"value":<id>,"match_by":"id"},
//	       "end":{"value":<id>,"match_by":"id"}[,"properties":{...}]}  // omitted when empty
//
// Field order is fixed (node: id,kinds,properties; edge: kind,start,end,[properties])
// and Properties preserves insertion order, so output stays diff-stable. Node ids
// and edge endpoints carry raw ARNs here; the colon->underscore id encoding is a
// terminal concern applied by the emit package (see encode.go), exactly as the
// Python does it at serialization time.
package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// isValidPropertyValue mirrors bhopengraph's is_valid_property_value: nil, a
// primitive, or a homogeneous slice of primitives. No maps, no nested lists.
func isValidPropertyValue(v any) bool {
	switch v.(type) {
	case nil, string, bool, int, int64, float64:
		return true
	case []string, []bool, []int, []int64, []float64:
		return true
	}
	return false
}

// Properties is an insertion-ordered bag of node/edge attributes.
type Properties struct {
	keys []string
	vals map[string]any
}

// NewProperties returns an empty Properties.
func NewProperties() *Properties { return &Properties{vals: make(map[string]any)} }

// Set stores key=value, preserving first-insertion order for stable output.
// It panics on an invalid value type, matching the Python's eager ValueError so
// bad properties fail where they are introduced rather than at ingest time.
func (p *Properties) Set(key string, value any) *Properties {
	if !isValidPropertyValue(value) {
		panic(fmt.Sprintf("graph: invalid property value for %q: %T", key, value))
	}
	if _, ok := p.vals[key]; !ok {
		p.keys = append(p.keys, key)
	}
	p.vals[key] = value
	return p
}

// Get returns the value for key, or nil if absent.
func (p *Properties) Get(key string) any { return p.vals[key] }

// Has reports whether key is set.
func (p *Properties) Has(key string) bool { _, ok := p.vals[key]; return ok }

// Len returns the number of properties.
func (p *Properties) Len() int { return len(p.keys) }

// Keys returns the property keys in insertion order.
func (p *Properties) Keys() []string { return append([]string(nil), p.keys...) }

// MarshalJSON emits the properties as a JSON object in insertion order.
func (p *Properties) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range p.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(p.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Node is an OpenGraph node. Kinds is capped at 3 (BHE limit); id is non-empty.
type Node struct {
	ID    string
	Kinds []NodeKind
	Props *Properties
}

// NewNode returns a node with the given id and initial kind.
func NewNode(id string, kind NodeKind) *Node {
	if id == "" {
		panic("graph: node id cannot be empty")
	}
	return &Node{ID: id, Kinds: []NodeKind{kind}, Props: NewProperties()}
}

// AddKind adds an additional kind (max 3, deduplicated).
func (n *Node) AddKind(k NodeKind) *Node {
	for _, existing := range n.Kinds {
		if existing == k {
			return n
		}
	}
	if len(n.Kinds) >= 3 {
		panic("graph: node can only have a maximum of 3 kinds")
	}
	n.Kinds = append(n.Kinds, k)
	return n
}

// Set adds a property to the node (chainable).
func (n *Node) Set(key string, value any) *Node { n.Props.Set(key, value); return n }

// MarshalJSON emits {"id":...,"kinds":[...],"properties":{...}} with properties
// ALWAYS present (even when empty), matching Node.to_dict in types.py.
func (n *Node) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"id":`)
	idb, err := json.Marshal(n.ID)
	if err != nil {
		return nil, err
	}
	b.Write(idb)
	b.WriteString(`,"kinds":`)
	kinds := n.Kinds
	if kinds == nil {
		kinds = []NodeKind{}
	}
	kb, err := json.Marshal(kinds)
	if err != nil {
		return nil, err
	}
	b.Write(kb)
	b.WriteString(`,"properties":`)
	props := n.Props
	if props == nil {
		props = NewProperties()
	}
	pb, err := props.MarshalJSON()
	if err != nil {
		return nil, err
	}
	b.Write(pb)
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Edge is a directed OpenGraph edge. Endpoints always match by id.
type Edge struct {
	Start string
	End   string
	Kind  EdgeKind
	Props *Properties
}

// NewEdge returns an edge start->end of the given kind.
func NewEdge(start, end string, kind EdgeKind) *Edge {
	if start == "" || end == "" {
		panic("graph: edge endpoints cannot be empty")
	}
	if kind == "" {
		panic("graph: edge kind cannot be empty")
	}
	return &Edge{Start: start, End: end, Kind: kind, Props: NewProperties()}
}

// Set adds a property to the edge (chainable).
func (e *Edge) Set(key string, value any) *Edge { e.Props.Set(key, value); return e }

// MarshalJSON emits {"kind":...,"start":{...},"end":{...}[,"properties":{...}]}.
// The properties key is OMITTED when empty (unlike Node), matching Edge.to_dict.
func (e *Edge) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"kind":`)
	kb, err := json.Marshal(e.Kind)
	if err != nil {
		return nil, err
	}
	b.Write(kb)
	b.WriteString(`,"start":{"value":`)
	sb, err := json.Marshal(e.Start)
	if err != nil {
		return nil, err
	}
	b.Write(sb)
	b.WriteString(`,"match_by":"id"},"end":{"value":`)
	eb, err := json.Marshal(e.End)
	if err != nil {
		return nil, err
	}
	b.Write(eb)
	b.WriteString(`,"match_by":"id"}`)
	if e.Props != nil && e.Props.Len() > 0 {
		b.WriteString(`,"properties":`)
		pb, err := e.Props.MarshalJSON()
		if err != nil {
			return nil, err
		}
		b.Write(pb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
