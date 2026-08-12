package model

// KMS collected shapes (AWSHound's KMSData / core/ingestion/kms.py; see the package
// doc for the shared conventions). Every key carries its readable policy/grants;
// customer-managed keys additionally carry tags and (for symmetric encrypt keys)
// a rotation flag.

import "encoding/json"

// KMSData is the top-level collected shape for AWS KMS: the account id plus every
// KMS key discovered across the account's enabled regions.
type KMSData struct {
	AccountId string   `json:"AccountId"`
	Keys      []KMSKey `json:"Keys"`
}

// KMSKey is one KMS key with DescribeKey metadata, readable policy/grants, and
// customer-managed-only tags/rotation. It mirrors the per-key collector shape.
//
//   - CreationDate is the metadata creation time rendered as a string, matching the
//     Python collector's str(CreationDate).
//   - KeyPolicy holds the parsed key-policy document (a JSON object), or is nil
//     when policy collection was denied/invalid. It round-trips unchanged.
//   - KeyPolicyKnown distinguishes a successfully collected empty policy from a
//     failed collection, so authorization can fail closed when policy is unknown.
//   - Grants are always non-nil and collected for every key when KMS permits it.
//     Tags remain empty for AWS-managed keys because those keys are not taggable.
//   - KeyRotationEnabled is a tri-state: a bool for a customer-managed symmetric
//     ENCRYPT_DECRYPT key, or nil (JSON null) otherwise — matching Python's None.
type KMSKey struct {
	KeyId              string          `json:"KeyId"`
	Arn                string          `json:"Arn"`
	Region             string          `json:"Region"`
	KeyState           string          `json:"KeyState"`
	KeyManager         string          `json:"KeyManager"`
	KeySpec            string          `json:"KeySpec"`
	KeyUsage           string          `json:"KeyUsage"`
	Origin             string          `json:"Origin"`
	Description        string          `json:"Description"`
	CreationDate       string          `json:"CreationDate"`
	Enabled            bool            `json:"Enabled"`
	MultiRegion        bool            `json:"MultiRegion"`
	Aliases            []KMSAlias      `json:"Aliases"`
	KeyPolicy          json.RawMessage `json:"KeyPolicy"`
	KeyPolicyKnown     bool            `json:"KeyPolicyKnown"`
	Grants             []KMSGrant      `json:"Grants"`
	Tags               []KMSTag        `json:"Tags"`
	KeyRotationEnabled *bool           `json:"KeyRotationEnabled"`
}

// KMSAlias is one alias pointing at a key (from ListAliases, grouped by
// TargetKeyId). The key node's "name" is derived from the first alias name.
type KMSAlias struct {
	AliasName string `json:"AliasName"`
	AliasArn  string `json:"AliasArn"`
}

// KMSGrant is one grant on a key (from ListGrants). Field order matches the Python
// collector's grant dict so the node's json-encoded "grants" property keys line
// up. CreationDate is the grant creation time as a string (Python str()).
type KMSGrant struct {
	GrantId           string              `json:"GrantId"`
	GranteePrincipal  string              `json:"GranteePrincipal"`
	RetiringPrincipal string              `json:"RetiringPrincipal"`
	Operations        []string            `json:"Operations"`
	Constraints       KMSGrantConstraints `json:"Constraints"`
	IssuingAccount    string              `json:"IssuingAccount"`
	CreationDate      string              `json:"CreationDate"`
}

// KMSGrantConstraints is a grant's encryption-context constraints. Both maps are
// omitempty so an unconstrained grant serializes as the empty object {} — matching
// the Python collector's grant.get("Constraints", {}) default.
type KMSGrantConstraints struct {
	EncryptionContextEquals map[string]string `json:"EncryptionContextEquals,omitempty"`
	EncryptionContextSubset map[string]string `json:"EncryptionContextSubset,omitempty"`
}

// KMSTag is one resource tag on a key (from ListResourceTags). KMS uses the
// TagKey/TagValue shape, which is distinct from the IAM model.Tag (Key/Value), so
// it is a separate type; the node's "tags" property serializes these verbatim.
type KMSTag struct {
	TagKey   string `json:"TagKey"`
	TagValue string `json:"TagValue"`
}
