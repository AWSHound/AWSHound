package build

import (
	"bytes"
	"encoding/json"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// KMSNodes emits the account's AWS_KMSKey nodes — the Go port of AWSHound's
// KMSKeyNodeParser (core/graph/nodes/kms.py). One node per KMS key, keyed by its
// ARN, with the exact property set the Python parser produces. Keys without an ARN
// are skipped (the Python parser's early continue). KMSKeyList returns keys in ARN
// order, so the output is diff-stable.
//
// The "name" is "<account>:<first alias>", falling back to "<account>:<key id>"
// when the key has no aliases. The aliases/key_policy/grants/tags properties are
// JSON-encoded strings, present only when non-empty (matching the Python `if x:`
// guards); they use Go's compact separators, the same convention as the IAM node
// parser's json-valued properties. key_rotation_enabled is emitted only when the
// key carries a rotation flag (customer-managed symmetric encrypt keys).
func KMSNodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	var nodes []*graph.Node
	for _, key := range a.KMSKeyList() {
		if key.Arn == "" {
			continue
		}

		aliasNames := kmsAliasNames(key.Aliases)
		nameSuffix := key.KeyId
		if len(aliasNames) > 0 {
			nameSuffix = aliasNames[0]
		}

		n := graph.NewNode(key.Arn, graph.KindKMSKey)
		n.Set("name", accountID+":"+nameSuffix)
		n.Set("arn", key.Arn)
		n.Set("account_id", accountID)
		n.Set("region", key.Region)
		n.Set("key_id", key.KeyId)
		n.Set("key_state", key.KeyState)
		n.Set("key_manager", key.KeyManager)
		n.Set("key_spec", key.KeySpec)
		n.Set("key_usage", key.KeyUsage)
		n.Set("origin", key.Origin)
		n.Set("description", key.Description)
		n.Set("creation_date", key.CreationDate)
		n.Set("enabled", key.Enabled)
		n.Set("multi_region", key.MultiRegion)

		if len(aliasNames) > 0 {
			n.Set("aliases", jsonProp(aliasNames))
		}
		if policy := kmsKeyPolicyJSON(key.KeyPolicy); policy != "" {
			n.Set("key_policy", policy)
		}
		if len(key.Grants) > 0 {
			n.Set("grants", jsonProp(key.Grants))
		}
		if len(key.Tags) > 0 {
			n.Set("tags", jsonProp(key.Tags))
		}
		if key.KeyRotationEnabled != nil {
			n.Set("key_rotation_enabled", *key.KeyRotationEnabled)
		}

		nodes = append(nodes, n)
	}

	return nodes
}

// kmsAliasNames extracts the non-empty alias names from a key's aliases, in order.
// Mirrors the Python parser's [a["AliasName"] for a in aliases if a["AliasName"]].
func kmsAliasNames(aliases []model.KMSAlias) []string {
	names := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if a.AliasName != "" {
			names = append(names, a.AliasName)
		}
	}
	return names
}

// kmsKeyPolicyJSON returns the key policy as a compact JSON string, or "" when the
// policy is absent (nil, empty, or the JSON null literal that a re-ingested
// AWS-managed key carries). Mirrors the Python parser's `if key_policy:` guard plus
// json.dumps(key_policy).
func kmsKeyPolicyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return ""
	}
	if s := buf.String(); s != "null" {
		return s
	}
	return ""
}
