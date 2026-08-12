package model

import "encoding/json"

// NormalizeGAADDocs re-stringifies IAM policy documents that boto3-captured GAAD
// files store as decoded JSON objects. The live aws-sdk-go-v2 collector returns
// them as URL-encoded strings (held as string in the model), so this accepts
// either form: it walks the JSON tree and converts object-valued document fields
// to their JSON-string form, leaving already-string documents untouched.
func NormalizeGAADDocs(raw []byte) ([]byte, error) {
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	docFields := map[string]bool{
		"AssumeRolePolicyDocument": true,
		"PolicyDocument":           true,
		"Document":                 true,
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				if docFields[k] {
					if _, isObj := val.(map[string]any); isObj {
						b, _ := json.Marshal(val)
						t[k] = string(b)
						continue
					}
				}
				t[k] = walk(val)
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		}
		return v
	}
	walk(tree)
	return json.Marshal(tree)
}
