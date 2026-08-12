package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
)

// Policy is a parsed AWS IAM policy document — an identity policy, a resource
// policy, or a role trust policy. AWS lets the top-level "Statement" be a single
// object or an array; both parse into Statements.
type Policy struct {
	Version    string
	Statements []Statement
}

// Statement is one statement of a policy document. Action/NotAction/Resource/
// NotResource are normalized to slices even when the document used a bare
// string; a nil slice means the key was absent, while a non-nil empty slice
// means it was present but empty. Principal/NotPrincipal are nil unless present
// (resource and trust policies only). Condition is nil when absent.
//
// Effect is the raw "Allow"/"Deny" string (the engine maps it to the Effect
// enum when compiling).
type Statement struct {
	Sid          string
	Effect       string
	Action       []string
	NotAction    []string
	Resource     []string
	NotResource  []string
	Principal    *Principal
	NotPrincipal *Principal
	Condition    Condition
}

// Principal is the Principal (or NotPrincipal) block of a resource/trust policy
// statement. AWS allows a bare "*" (anyone/anonymous) or an object keyed by
// principal type; each key's value may be a single string or an array.
type Principal struct {
	// Wildcard is true when the block was the bare JSON string "*"; the keyed
	// slices below are then empty.
	Wildcard      bool
	AWS           []string
	Service       []string
	Federated     []string
	CanonicalUser []string
}

// Condition is a policy Condition block in AWS's canonical three-level form:
// operator -> condition key -> values. A single value is normalized to a
// one-element slice, and a non-string scalar value (a JSON bool or number, both
// of which AWS accepts) is coerced to its textual form. This mirrors the shape
// produced by the Python engine's normalize_condition.
type Condition map[string]map[string][]string

// ParsePolicyDocument decodes a URL-encoded IAM policy document (as returned by
// the IAM GetAccountAuthorizationDetails / GetRole APIs and carried on the model
// InlinePolicy.PolicyDocument, RoleDetail.AssumeRolePolicyDocument, and
// PolicyVersion.Document fields) and parses it into a Policy.
//
// The document is percent-encoded, so it is decoded with url.PathUnescape, which
// decodes %XX escapes but leaves "+" untouched — matching Python's
// urllib.parse.unquote so the decoded JSON is byte-for-byte what the Python
// evaluator parses. (url.QueryUnescape would additionally rewrite "+" into a
// space, corrupting any literal "+" inside a decoded string value — e.g. an ARN
// or condition value — and that divergence would surface as wrong attack paths.)
// If decoding fails — e.g. the input is already plain JSON — the raw input is
// parsed as a best-effort fallback.
func ParsePolicyDocument(doc string) (*Policy, error) {
	decoded, err := url.PathUnescape(doc)
	if err != nil {
		decoded = doc
	}
	var policy Policy
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		return nil, fmt.Errorf("eval: parse policy document: %w", err)
	}
	return &policy, nil
}

// UnmarshalJSON parses a policy document, accepting a single Statement object or
// an array of statements. Unknown top-level keys (e.g. "Id") are ignored.
func (p *Policy) UnmarshalJSON(data []byte) error {
	var raw struct {
		Version   string
		Statement json.RawMessage
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Version = raw.Version
	p.Statements = nil
	trimmed := bytes.TrimSpace(raw.Statement)
	if len(trimmed) == 0 || bytes.Equal(trimmed, jsonNull) {
		return nil
	}
	if trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &p.Statements)
	}
	var single Statement
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	p.Statements = []Statement{single}
	return nil
}

// UnmarshalJSON decodes a statement, normalizing the string-or-array policy
// fields (Action/NotAction/Resource/NotResource) to slices.
func (st *Statement) UnmarshalJSON(data []byte) error {
	var raw struct {
		Sid          string
		Effect       string
		Action       stringOrSlice
		NotAction    stringOrSlice
		Resource     stringOrSlice
		NotResource  stringOrSlice
		Principal    *Principal
		NotPrincipal *Principal
		Condition    Condition
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	st.Sid = raw.Sid
	st.Effect = raw.Effect
	st.Action = []string(raw.Action)
	st.NotAction = []string(raw.NotAction)
	st.Resource = []string(raw.Resource)
	st.NotResource = []string(raw.NotResource)
	st.Principal = raw.Principal
	st.NotPrincipal = raw.NotPrincipal
	st.Condition = raw.Condition
	return nil
}

// UnmarshalJSON decodes a Principal block: either the bare string "*" or an
// object keyed by principal type whose values may each be a string or an array.
func (p *Principal) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, jsonNull) {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		p.Wildcard = s == "*"
		return nil
	}
	var obj struct {
		AWS           stringOrSlice
		Service       stringOrSlice
		Federated     stringOrSlice
		CanonicalUser stringOrSlice
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return err
	}
	p.AWS = []string(obj.AWS)
	p.Service = []string(obj.Service)
	p.Federated = []string(obj.Federated)
	p.CanonicalUser = []string(obj.CanonicalUser)
	return nil
}

// UnmarshalJSON decodes a Condition block into the canonical three-level form,
// normalizing single values to one-element slices.
func (c *Condition) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, jsonNull) {
		*c = nil
		return nil
	}
	// operator -> key -> (string | number | bool | array); stringOrSlice coerces
	// each innermost value to []string.
	var raw map[string]map[string]stringOrSlice
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	out := make(Condition, len(raw))
	for op, kv := range raw {
		inner := make(map[string][]string, len(kv))
		for key, vals := range kv {
			inner[key] = []string(vals)
		}
		out[op] = inner
	}
	*c = out
	return nil
}

// jsonNull is the JSON literal null, compared against trimmed field bytes.
var jsonNull = []byte("null")

// stringOrSlice unmarshals an AWS-policy value that is either a single scalar or a
// JSON array of scalars. AWS lets Action/Resource, Principal sub-keys, and
// Condition values each be a bare string or an array. Non-string scalars (a JSON
// bool or number, valid in Condition values) are coerced to their textual form
// so such policies still parse — matching the Python side, which decodes JSON
// natively and never fails on them.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, jsonNull) {
		*s = nil
		return nil
	}
	if trimmed[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return err
		}
		out := make(stringOrSlice, 0, len(raw))
		for _, elem := range raw {
			v, err := scalarToString(elem)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		*s = out
		return nil
	}
	v, err := scalarToString(trimmed)
	if err != nil {
		return err
	}
	*s = stringOrSlice{v}
	return nil
}

// scalarToString renders a single JSON scalar as a string: a JSON string is
// unquoted, a bool/number is taken verbatim (AWS stringifies these in condition
// values), and JSON null becomes "".
func scalarToString(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, jsonNull) {
		return "", nil
	}
	if trimmed[0] == '"' {
		var str string
		if err := json.Unmarshal(trimmed, &str); err != nil {
			return "", err
		}
		return str, nil
	}
	return string(trimmed), nil
}
