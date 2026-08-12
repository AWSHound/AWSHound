package edges

// This file ports the credential family (core/graph/edges/credential/): the 17
// SimpleActionEdgeProcessors covering IAM credential-management attack paths —
// access keys (create/update/delete), login profiles (create/update/delete),
// service-specific credentials (create/reset/delete), SSH public keys
// (upload/update/delete), and MFA devices (create-virtual/enable/deactivate/
// delete-virtual/resync).
//
// Every processor is an instance of SimpleActionEdgeProcessor with
// _target_getter = "get_user_arns": it checks one iam:* action from each
// principal (user or role) against every IAM *user* in the same account and
// emits an edge when the action is allowed. Only CanCreateAccessKey,
// CanCreateLoginProfile, and CanUpdateLoginProfile are traversable
// (each processor's _is_traversable); the rest are not. The family has no meta
// edges.
//
// Fidelity notes:
//   - Candidate principals are users + roles only (Python's
//     get_all_principal_arns excludes groups); users are also the only edge
//     *targets*, so a user with the action on itself yields a self-edge
//     (start == end) — the base processor performs no self-exclusion.
//   - make_edge_properties emits exactly (is_traversable, allow_sources,
//     conditions) in that insertion order; permissionEdge reproduces it.

import (
	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// credentialSpec describes one SimpleActionEdgeProcessor in the family: the IAM
// action it checks, the edge kind it emits, and whether the emitted edge is
// traversable. Targets are always the account's IAM users
// (_target_getter = "get_user_arns"), so they are not part of the spec.
type credentialSpec struct {
	action      string
	kind        graph.EdgeKind
	traversable bool
}

// credentialSpecs ports core/graph/edges/credential/*.py one-to-one. Grouped by
// resource type for readability; the traversable flag mirrors each processor's
// _is_traversable and the action mirrors its _action.
var credentialSpecs = []credentialSpec{
	// Access keys.
	{"iam:CreateAccessKey", graph.KindCanCreateAccessKey, true},
	{"iam:UpdateAccessKey", graph.KindCanUpdateAccessKey, false},
	{"iam:DeleteAccessKey", graph.KindCanDeleteAccessKey, false},

	// Login profiles.
	{"iam:CreateLoginProfile", graph.KindCanCreateLoginProfile, true},
	{"iam:UpdateLoginProfile", graph.KindCanUpdateLoginProfile, true},
	{"iam:DeleteLoginProfile", graph.KindCanDeleteLoginProfile, false},

	// Service-specific credentials.
	{"iam:CreateServiceSpecificCredential", graph.KindCanCreateServiceSpecificCredential, false},
	{"iam:ResetServiceSpecificCredential", graph.KindCanResetServiceSpecificCredential, false},
	{"iam:DeleteServiceSpecificCredential", graph.KindCanDeleteServiceSpecificCredential, false},

	// SSH public keys.
	{"iam:UploadSSHPublicKey", graph.KindCanUploadSSHPublicKey, false},
	{"iam:UpdateSSHPublicKey", graph.KindCanUpdateSSHPublicKey, false},
	{"iam:DeleteSSHPublicKey", graph.KindCanDeleteSSHPublicKey, false},

	// MFA devices.
	{"iam:CreateVirtualMFADevice", graph.KindCanCreateVirtualMFADevice, false},
	{"iam:EnableMFADevice", graph.KindCanEnableMFADevice, false},
	{"iam:DeactivateMFADevice", graph.KindCanDeactivateMFADevice, false},
	{"iam:DeleteVirtualMFADevice", graph.KindCanDeleteVirtualMFADevice, false},
	{"iam:ResyncMFADevice", graph.KindCanResyncMFADevice, false},
}

// CredentialSpecs exposes the credential family as generic identity-governed edge
// specs (every processor targets IAM users). This is the family's declaration in
// the shared spec table (§10 of docs/authorization-tensor.md); the driver
// (GenerateIdentityGovernedEdges) reproduces CredentialEdges' output from it.
func CredentialSpecs() []IdentitySpec {
	out := make([]IdentitySpec, 0, len(credentialSpecs))
	for _, c := range credentialSpecs {
		out = append(out, IdentitySpec{
			Action: c.action, Kind: c.kind, TargetType: "user", Traversable: c.traversable,
		})
	}
	return out
}

// CredentialEdges emits the credential family's attack-path edges for every
// account in the store. For each account it runs all 17 SimpleActionEdgeProcessors:
// every candidate principal (user or role that references the action) is checked
// against every IAM user in the account, and an edge is emitted when
// CanPerformAction allows it. Ports core/graph/edges/credential/.
//
// Accounts are processed in ascending id order and candidates/targets are sorted
// so output is deterministic. The action->principals pre-filter bitmaps are
// global, so they are memoised across accounts.
func CredentialEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	// Migrated to the generic spec driver (§10): every credential processor is an
	// identity-governed edge to an IAM user, so the driver's type filter
	// (targetType "user") + factor evaluation reproduce the family exactly. The
	// per-account principal pre-filter the legacy scan used was only an
	// optimization — CanPerformAction rejects the same principals the bitmap
	// pre-filter would, so the edge set is identical (see
	// TestCredentialFamilyEqualsSpecDriver).
	var out []*graph.Edge
	for _, spec := range CredentialSpecs() {
		out = append(out, GenerateIdentityGovernedEdges(s, pe, spec)...)
	}
	return out
}

// credentialPrincipalsWith returns the set of principal ARNs (users + roles, any
// account) whose identity policies grant action against at least one interned
// resource — the Go equivalent of policy_evaluator.principals_with_action used as
// the cheap pre-filter. Memoised across accounts. Safe here because every target
// is a real interned user ARN: any principal this drops has no allow statement
// that could match a user, so CanPerformAction on that user would deny it anyway.
func credentialPrincipalsWith(s *store.Store, pe *eval.PolicyEvaluator, memo map[string]map[string]bool, action string) map[string]bool {
	if set, ok := memo[action]; ok {
		return set
	}
	bm := pe.PrincipalsWithAction(action, "*")
	set := make(map[string]bool)
	for _, id := range bm.ToArray() {
		if arn := s.ARN().Arn(id); arn != "" {
			set[arn] = true
		}
	}
	memo[action] = set
	return set
}
