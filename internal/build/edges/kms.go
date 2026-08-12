// This file ports the KMS attack-path family (core/graph/edges/kms/) plus the
// KMS Read/All meta edges (core/graph/edges/meta/, see kms_meta.go). It emits
// principal -> {key, account} edges for every KMS capability the 3-layer KMS
// authorization model grants, then consolidates the crypto/grant/policy/lifecycle
// constituents into the two KMS meta edges.
//
// The 3-layer KMS model (core/graph/edges/kms/_kms_auth_helpers.py). Unlike S3,
// KMS access does NOT flow from IAM alone: it is the union of three layers,
// evaluated in order with deny-wins short-circuits:
//
//	Layer 1  key policy — a direct allow/deny naming the principal (root ARNs are
//	         NOT expanded here; that pattern is the Layer-2 delegation signal).
//	Layer 2  IAM policy — consulted ONLY when the key policy delegates to IAM
//	         (a statement granting kms:*/"*" to the account root). This is the one
//	         layer CanPerformAction covers.
//	Layer 3  grants — a grant naming the principal as grantee for the action's
//	         grant operation (14 grantable ops; lifecycle/policy actions are not
//	         grantable).
//
// So each edge is gated by kmsCanPerformAction, which composes all three — not by
// CanPerformAction alone (that would miss key-policy direct grants and grants).
//
// Scope. KMS edges are WITHIN an account: each Python processor runs per account
// with get_all_principal_arns(account) x get_kms_data(account), so a principal
// only earns a KMS edge to a key in its OWN account (no global aggregation like
// S3). This port preserves that by iterating per account. Principals are users +
// roles only (get_all_principal_arns), never groups.
//
// Context fidelity. Key-policy and identity conditions share the store-backed
// request context. KMS adds CallerAccount and marks ViaService absent for these
// direct principal-to-key checks, so a service-mediated policy does not become a
// direct capability under attacker-favorable unknown-condition bias.
//
// Endpoints carry raw ARNs (the colon->underscore id encoding is a terminal
// concern of the emit package); the key ARN and account-root ARN are synthesized
// identically to the KMS/IAM node builders so every edge connects to a real node.
// The final edge slice is sorted by (start, end, kind) for diff-stable output.
package edges

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// kmsSimpleSpec binds one KMS action to its edge kind and whether the processor
// only applies to customer-managed keys. It captures the shape shared by the
// seven SimpleKmsEdgeProcessor subclasses (crypto + grant + lifecycle + policy):
// for each key in a state that supports the operation, for each principal, emit
// principal -> key when kmsCanPerformAction allows the action. Ported from
// core/graph/edges/kms/_base.py.
type kmsSimpleSpec struct {
	action       string
	kind         graph.EdgeKind
	customerOnly bool
}

// kmsSimpleSpecs are the seven SimpleKmsEdgeProcessor bindings. Decrypt/Encrypt/
// GenerateDataKey/CreateGrant apply to every key; DisableKey/ScheduleKeyDeletion/
// PutKeyPolicy are _customer_only (they are meaningless on AWS-managed keys, which
// are not editable). CanSelfGrantKmsOps and CanListKmsKeys are shaped differently
// and handled separately below.
var kmsSimpleSpecs = []kmsSimpleSpec{
	{"kms:Decrypt", graph.KindCanDecryptKMSKey, false},
	{"kms:Encrypt", graph.KindCanEncryptKMSKey, false},
	{"kms:GenerateDataKey", graph.KindCanGenerateKMSDataKey, false},
	{"kms:CreateGrant", graph.KindCanCreateKMSGrant, false},
	{"kms:PutKeyPolicy", graph.KindCanModifyKMSKeyPolicy, true},
	{"kms:DisableKey", graph.KindCanDisableKMSKey, true},
	{"kms:ScheduleKeyDeletion", graph.KindCanScheduleKMSKeyDeletion, true},
}

// kmsGrantableOperations are the 14 operations a KMS grant can delegate. Ported
// verbatim (order preserved) from CanSelfGrantKmsOpsEdgeProcessor's
// KMS_GRANTABLE_OPERATIONS — a principal with kms:CreateGrant can name itself
// grantee for any of these, so CreateGrant transitively implies all of them.
var kmsGrantableOperations = []string{
	"Decrypt",
	"Encrypt",
	"GenerateDataKey",
	"GenerateDataKeyPair",
	"GenerateDataKeyPairWithoutPlaintext",
	"GenerateDataKeyWithoutPlaintext",
	"GenerateMac",
	"ReEncryptFrom",
	"ReEncryptTo",
	"Sign",
	"Verify",
	"VerifyMac",
	"DeriveSharedSecret",
	"CreateGrant",
}

// kmsGrantableOperationsJSON is the json.dumps(KMS_GRANTABLE_OPERATIONS) string
// carried on every CanSelfGrantKmsOps edge's grantable_operations property.
var kmsGrantableOperationsJSON = func() string {
	b, _ := json.Marshal(kmsGrantableOperations)
	return string(b)
}()

// KMSEdges emits the KMS family's attack-path edges for the whole store: the
// per-permission constituents (decrypt/encrypt/generate-data-key, create-grant,
// self-grant, modify-key-policy, disable, schedule-deletion, list-keys) and the
// KMSKey Read/All meta edges consolidated from the key-scoped ones.
func KMSEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })

	// Compile each key's policy + IAM delegation once (pure function of key +
	// account, independent of principal/action) into an index the scan driver's
	// Eval closures reuse. KMS edges never cross account boundaries.
	type kmsKeyCtx struct {
		key *model.KMSKey
		kp  kmsKeyPolicy
	}
	keyIdx := map[string]kmsKeyCtx{}
	var allKeys, customerKeys []string
	for _, a := range accounts {
		for _, key := range a.KMSKeyList() {
			if key.Arn == "" {
				continue
			}
			keyIdx[key.Arn] = kmsKeyCtx{key: key, kp: kmsCompileKeyPolicy(key, a.ID)}
			allKeys = append(allKeys, key.Arn)
			if key.KeyManager == "CUSTOMER" {
				customerKeys = append(customerKeys, key.Arn)
			}
		}
	}
	sort.Strings(allKeys)
	sort.Strings(customerKeys)

	// Wave 0 — the seven per-permission constituents via the shared scan driver
	// (§10): each is a gated (key-policy/IAM-delegation/grant) evaluation of a
	// principal against a key in its own account, so it supplies an EvalFunc
	// wrapping kmsCanPerformAction. customerOnly specs draw only customer keys.
	var constituents []*graph.Edge
	for _, spec := range kmsSimpleSpecs {
		cands := allKeys
		if spec.customerOnly {
			cands = customerKeys
		}
		action := spec.action
		constituents = append(constituents, GenerateScanEdges(s, ScanSpec{
			Kind:       spec.kind,
			Candidates: func(*store.Store) []string { return cands },
			Eval: func(principal, keyArn string) EvalResult {
				kc := keyIdx[keyArn]
				if !kmsActionUsableInState(action, kc.key) {
					return EvalResult{}
				}
				res := kmsCanPerformAction(pe, kc.key, kc.kp, principal, action)
				return EvalResult{Allowed: res.Allowed, AllowSources: res.AllowSources, Conditions: res.Conditions}
			},
		})...)
	}

	// ListKeys is account-scoped (action on "*" → account root, "conditions" key) —
	// generated via the shared driver.
	constituents = append(constituents, GenerateAccountScopedEdges(s, pe, "kms:ListKeys", graph.KindCanListKMSKeys, "conditions")...)

	// Self-grant (transitive CreateGrant, bespoke grantable_operations property) via
	// the scan driver with a gated EvalFunc and a custom EdgeFn.
	constituents = append(constituents, GenerateScanEdges(s, ScanSpec{
		Kind:       graph.KindCanSelfGrantKMSOps,
		Candidates: func(*store.Store) []string { return allKeys },
		Eval: func(principal, keyArn string) EvalResult {
			kc := keyIdx[keyArn]
			if !kmsActionUsableInState("kms:CreateGrant", kc.key) {
				return EvalResult{}
			}
			res := kmsCanPerformAction(pe, kc.key, kc.kp, principal, "kms:CreateGrant")
			return EvalResult{Allowed: res.Allowed, AllowSources: res.AllowSources, Conditions: res.Conditions}
		},
		EdgeFn: func(principal, keyArn string, r EvalResult) *graph.Edge {
			e := graph.NewEdge(principal, keyArn, graph.KindCanSelfGrantKMSOps)
			e.Set("is_traversable", false)
			e.Set("allow_sources", strings.Join(r.AllowSources, ", "))
			e.Set("conditions", conditionsJSON(r.Conditions))
			e.Set("grantable_operations", kmsGrantableOperationsJSON)
			return e
		},
	})...)

	// Waves 1-2 — meta edges (KMSKeyAll, then KMSKeyRead) + suppression of the
	// constituents they consume.
	out := kmsApplyMetaWaves(constituents)

	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return string(out[i].Kind) < string(out[j].Kind)
	})
	return out
}

// kmsActionUsableInState applies the live KMS operation/key-state matrix before
// authorization or meta-edge composition. Crypto and grant use requires an
// enabled key; edit/lifecycle operations used by this graph are available for
// enabled or disabled customer keys. Pending deletion states support none of the
// modeled direct capabilities (CancelKeyDeletion is intentionally not modeled).
func kmsActionUsableInState(action string, key *model.KMSKey) bool {
	if key == nil {
		return false
	}
	switch action {
	case "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:CreateGrant", "kms:DisableKey":
		return key.KeyState == "Enabled"
	case "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy":
		return key.KeyState == "Enabled" || key.KeyState == "Disabled"
	default:
		return key.KeyState != "PendingDeletion" && key.KeyState != "PendingReplicaDeletion"
	}
}

// kmsConstituentEdge builds a per-permission KMS edge. The KMS SimpleKmsEdge
// processors route through make_edge_properties(result, is_traversable=False), so
// unlike the S3 constituents these carry is_traversable (=false) as their first
// property, then allow_sources, then conditions.
func kmsConstituentEdge(start, end string, kind graph.EdgeKind, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, end, kind)
	e.Set("is_traversable", false)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set("conditions", conditionsJSON(res.Conditions))
	return e
}

// kmsSelfGrantEdge builds a CanSelfGrantKmsOps edge, adding the constant
// grantable_operations property after the standard three. Ported from
// CanSelfGrantKmsOpsEdgeProcessor's Properties(...) call.
func kmsSelfGrantEdge(start, end string, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, end, graph.KindCanSelfGrantKMSOps)
	e.Set("is_traversable", false)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set("conditions", conditionsJSON(res.Conditions))
	e.Set("grantable_operations", kmsGrantableOperationsJSON)
	return e
}

// kmsListKeysEdge builds a CanListKmsKeys edge (principal -> account node). Ported
// from CanListKmsKeysEdgeProcessor's Properties(is_traversable=False, ...).
func kmsListKeysEdge(start, accountRoot string, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, accountRoot, graph.KindCanListKMSKeys)
	e.Set("is_traversable", false)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set("conditions", conditionsJSON(res.Conditions))
	return e
}
