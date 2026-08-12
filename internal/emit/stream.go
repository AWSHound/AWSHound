package emit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/AWSHound/AWSHound/internal/graph"
)

// StreamGraphFromBuilt reads a built.json document (raw ARN ids, as written by
// graph.WriteBuilt / the streaming build) and writes the final OpenGraph JSON to
// w — encoding ids at this terminal step — without ever holding the whole graph
// in memory. It decodes the nodes and edges arrays element by element, so peak
// memory is one node/edge, letting the `all` command emit graph.json straight
// from a streamed built.json (§9 of docs/authorization-tensor.md).
//
// Output is byte-identical to WriteGraph on the same nodes/edges. The built.json
// section order (nodes then edges) is preserved.
func StreamGraphFromBuilt(r io.Reader, w io.Writer) error {
	return streamGraphFromBuilt(r, w, nil)
}

// StreamGraphFromBuiltCounted is the bounded stream with element counts for the
// standalone emit command's summary and metrics.
func StreamGraphFromBuiltCounted(r io.Reader, w io.Writer) (nodeCount, edgeCount int, err error) {
	err = streamGraphFromBuilt(r, w, func(section string) {
		if section == "nodes" {
			nodeCount++
		} else if section == "edges" {
			edgeCount++
		}
	})
	return
}

func streamGraphFromBuilt(r io.Reader, w io.Writer, onElement func(string)) error {
	dec := json.NewDecoder(r)
	bw := bufio.NewWriter(w)

	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	if _, err := bw.WriteString(`{"graph":{`); err != nil {
		return err
	}

	firstSection := true
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("emit: expected section key, got %v", keyTok)
		}
		if err := expectDelim(dec, '['); err != nil {
			return err
		}
		if !firstSection {
			if err := bw.WriteByte(','); err != nil {
				return err
			}
		}
		firstSection = false
		if _, err := bw.WriteString(`"` + key + `":[`); err != nil {
			return err
		}

		first := true
		for dec.More() {
			if !first {
				if err := bw.WriteByte(','); err != nil {
					return err
				}
			}
			first = false
			b, err := decodeEncode(dec, key)
			if err != nil {
				return err
			}
			if onElement != nil {
				onElement(key)
			}
			if _, err := bw.Write(b); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return err
		}
		if err := bw.WriteByte(']'); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return err
	}
	if _, err := bw.WriteString(`},"metadata":{"source_kind":"` + SourceKind + `"}}`); err != nil {
		return err
	}
	return bw.Flush()
}

// decodeEncode decodes one element of the named section and returns its final
// (id-encoded) JSON, mirroring WriteGraph's per-element encoding.
func decodeEncode(dec *json.Decoder, section string) ([]byte, error) {
	switch section {
	case "nodes":
		var n graph.Node
		if err := dec.Decode(&n); err != nil {
			return nil, err
		}
		n.ID = graph.EncodeID(n.ID)
		return n.MarshalJSON()
	case "edges":
		var e graph.Edge
		if err := dec.Decode(&e); err != nil {
			return nil, err
		}
		e.Start = graph.EncodeID(e.Start)
		e.End = graph.EncodeID(e.End)
		return e.MarshalJSON()
	default:
		return nil, fmt.Errorf("emit: unknown built section %q", section)
	}
}

// expectDelim consumes the next token and errors unless it is the given delimiter.
func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return fmt.Errorf("emit: expected %q, got %v", d, tok)
	}
	return nil
}
