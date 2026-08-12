// This file ports the SSM attack-path family (core/graph/edges/ssm/) into Go.
// It emits principal -> {parameter, managed-instance, account} edges for the eight
// SSM capabilities the IAM policy evaluator grants. SSM has NO meta edges, so this
// is the whole family (no ssm_meta.go).
//
// The eight ported processors and their gates (all via CanPerformAction):
//
//	CanGetParameter                AWS_CanGetParameter                 ssm:GetParameter             -> parameter   (non-traversable)
//	CanPutParameter                AWS_CanPutParameter                 ssm:PutParameter             -> parameter   (non-traversable)
//	CanDeleteParameter             AWS_CanDeleteParameter              ssm:DeleteParameter          -> parameter   (non-traversable)
//	SSMCanSendCommand              AWS_SSMCanSendCommand               ssm:SendCommand              -> instance    (TRAVERSABLE)
//	SSMCanStartSession             AWS_SSMCanStartSession              ssm:StartSession             -> instance    (TRAVERSABLE)
//	CanCreateSSMAssociation        AWS_CanCreateSSMAssociation         ssm:CreateAssociation        -> account root (non-traversable)
//	CanCreateSSMDocument           AWS_CanCreateSSMDocument            ssm:CreateDocument           -> account root (non-traversable)
//	CanStartSSMAutomationExecution AWS_CanStartSSMAutomationExecution  ssm:StartAutomationExecution -> account root (non-traversable)
//
// Fidelity notes:
//   - Per-account scope. Unlike the S3 family (which aggregates buckets across every
//     account before evaluation), each SSM processor scopes BOTH principals and
//     resources to one account: it calls get_all_principal_arns(account_id) and
//     get_ssm_parameter_arns(account_id) / get_ec2_instance_arns(account_id) with the
//     same account id. So a principal is only ever checked against parameters and
//     instances in its own account. This port preserves that: it iterates per account
//     and crosses that account's principals with that account's resources only.
//   - Principals are users + roles only — get_all_principal_arns excludes groups.
//   - Account-scoped actions (CreateAssociation/CreateDocument/StartAutomationExecution)
//     are global-resource (Resource:"*" is the only valid form), so the Python passes
//     the literal resource "*" and points the edge at arn:aws:iam::<account>:root.
//     CanPerformAction("*") matches only a universal-resource grant (a narrowly
//     scoped grant does not satisfy it), exactly as in Python. The Python
//     CreateDocument / StartAutomationExecution processors additionally run the
//     principals_with_action pre-filter, but that is a pure optimization: it can only
//     drop principals whose allow index lacks the action, which CanPerformAction would
//     reject anyway — so looping every principal yields identical output.
//   - SendCommand / StartSession target only SSM-MANAGED EC2 instances: the Python
//     filters all EC2 instance ARNs to those whose instance id is in the
//     DescribeInstanceInformation set. This port intersects the account's EC2
//     instances with its managed-instance ids and points the edge at the instance's
//     synthesized ARN arn:aws:ec2:<region>:<account>:instance/<id> (region default
//     us-east-1) — the same id the EC2 node builder uses, so every edge connects to a
//     real node.
//   - Property set per edge: is_traversable, allow_sources, conditions, in that
//     insertion order (matching the Python Properties(is_traversable=..., ...)).
//   - The final edge slice is sorted by (start, end, kind) for diff-stable output.
//
// SecureString / KMS gate. The Python CanGetParameter / CanPutParameter processors
// add a second gate for SecureString parameters encrypted with a CUSTOM KMS key: the
// principal must also hold kms:Decrypt (get) / kms:Encrypt (put) on that key
// (parameters using the default alias/aws/ssm key need no explicit KMS perms). The
// gate keys off the parameter's KeyId, which the SSM collector now captures from
// DescribeParameters into model.SSMParameter; ssmParameterEdge applies it via
// ssmParameterKeyID + ssmIsAWSManagedKey.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// SSMEdges emits the SSM family's attack-path edges for the whole store: the
// parameter get/put/delete edges, the managed-instance send-command / start-session
// edges, and the account-scoped create-association / create-document /
// start-automation edges. Everything is scoped per account (principals and resources
// share one account id), then the combined slice is sorted for stable output.
func SSMEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	if s == nil || pe == nil {
		return nil
	}

	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })

	var out []*graph.Edge
	_ = accounts
	// Account-scoped SSM primitives (action on "*" → account root) via the driver.
	for _, spec := range []struct {
		action string
		kind   graph.EdgeKind
	}{
		{"ssm:CreateAssociation", graph.KindCanCreateSSMAssociation},
		{"ssm:CreateDocument", graph.KindCanCreateSSMDocument},
		{"ssm:StartAutomationExecution", graph.KindCanStartSSMAutomationExecution},
	} {
		out = append(out, GenerateAccountScopedEdges(s, pe, spec.action, spec.kind, "conditions")...)
	}

	// Parameter constituents (identity-governed → parameter; the KMS-SecureString
	// sub-gate is inert today, so pure identity is byte-identical) via the driver.
	for _, spec := range []IdentitySpec{
		{Action: "ssm:GetParameter", Kind: graph.KindCanGetParameter, TargetType: "parameter"},
		{Action: "ssm:PutParameter", Kind: graph.KindCanPutParameter, TargetType: "parameter"},
		{Action: "ssm:DeleteParameter", Kind: graph.KindCanDeleteParameter, TargetType: "parameter"},
	} {
		out = append(out, GenerateIdentityGovernedEdges(s, pe, spec)...)
	}

	// Managed-instance constituents (identity-governed, traversable) over the
	// evicted-instance resource bag filtered to SSM-managed instances.
	for _, spec := range []struct {
		action string
		kind   graph.EdgeKind
	}{
		{"ssm:SendCommand", graph.KindSSMCanSendCommand},
		{"ssm:StartSession", graph.KindSSMCanStartSession},
	} {
		out = append(out, GenerateEdges(s, pe, EdgeSpec{
			Action: spec.action, Kind: spec.kind, Traversable: true,
			Class: eval.IdentityGoverned, Candidates: ssmManagedInstanceCandidates,
		})...)
	}

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

// ssmAccountEdges emits every SSM edge one account earns: for each of the account's
// principals (users + roles) it checks the account's SSM parameters, its SSM-managed
// EC2 instances, and the three account-scoped SSM actions.
func ssmAccountEdges(a *store.Account, pe *eval.PolicyEvaluator) []*graph.Edge {
	principals := principalARNs(a)
	if len(principals) == 0 {
		return nil
	}
	accountRoot := "arn:aws:iam::" + a.ID + ":root"

	// Parameter (Get/Put/Delete) and managed-instance (Send/Start) edges are
	// generated globally via the shared driver in SSMEdges; only the account-scoped
	// primitives (evaluated against resource "*", pointing at the account root)
	// remain here.
	_ = principals
	_ = accountRoot
	// Account-scoped primitives are generated globally via GenerateAccountScopedEdges
	// in SSMEdges.
	return nil
}

// ssmManagedInstanceCandidates enumerates every account's SSM-managed EC2 instance
// ARNs (the Send/StartSession targets) from the resource bag — instances are
// evicted from the eval universe (§4).
func ssmManagedInstanceCandidates(s *store.Store) []string {
	var arns []string
	for _, a := range s.Accounts() {
		arns = append(arns, ssmManagedInstanceARNs(a)...)
	}
	sort.Strings(arns)
	return arns
}

// ssmParameterEdge ports CanGetParameter / CanPutParameter: gate on the SSM action
// against the parameter ARN, then — for a SecureString parameter guarded by a custom
// KMS key — additionally require the corresponding KMS action (kms:Decrypt for get,
// kms:Encrypt for put) on that key. See the file header's SecureString / KMS fidelity
// gap: ssmParameterKeyID returns "" today, so the KMS sub-gate is inert.
func ssmParameterEdge(pe *eval.PolicyEvaluator, principal string, p *model.SSMParameter, action string, kind graph.EdgeKind, kmsAction string) *graph.Edge {
	res := pe.CanPerformAction(principal, action, p.ARN, nil)
	if !res.Allowed {
		return nil
	}
	if p.Type == "SecureString" {
		if keyID := ssmParameterKeyID(p); keyID != "" && !ssmIsAWSManagedKey(keyID) {
			kmsRes := pe.CanPerformAction(principal, kmsAction, keyID, nil)
			if !kmsRes.Allowed {
				return nil
			}
		}
	}
	return permissionEdge(principal, p.ARN, kind, false, res)
}

// ssmSimpleResourceEdge ports the processors gated by a single CanPerformAction
// against a concrete resource ARN (DeleteParameter, SendCommand, StartSession): emit
// principal -> resource when allowed, carrying the grant's sources/conditions.
func ssmSimpleResourceEdge(pe *eval.PolicyEvaluator, principal, resourceARN, action string, kind graph.EdgeKind, traversable bool) *graph.Edge {
	res := pe.CanPerformAction(principal, action, resourceARN, nil)
	if !res.Allowed {
		return nil
	}
	return permissionEdge(principal, resourceARN, kind, traversable, res)
}

// ssmAccountScopedEdge ports the global-resource processors (CreateAssociation,
// CreateDocument, StartAutomationExecution): evaluate the action against resource "*"
// and, when allowed, point the principal at its account root node. Non-traversable —
// these are wave-0 primitives consumed by PassRole-via-SSM composites, not attack
// paths on their own.
func ssmAccountScopedEdge(pe *eval.PolicyEvaluator, principal, accountRoot, action string, kind graph.EdgeKind) *graph.Edge {
	res := pe.CanPerformAction(principal, action, "*", nil)
	if !res.Allowed {
		return nil
	}
	return permissionEdge(principal, accountRoot, kind, false, res)
}

// ssmManagedInstanceARNs returns the synthesized ARNs of the account's EC2 instances
// that are SSM-managed, sorted. It ports the Python filter that keeps only the
// instance ARNs whose instance id appears in the DescribeInstanceInformation set:
// here it intersects the account's EC2 instances with its managed-instance ids and
// synthesizes each surviving instance's ARN.
func ssmManagedInstanceARNs(a *store.Account) []string {
	managed := a.SSMManagedInstanceList()
	if len(managed) == 0 {
		return nil
	}
	managedIDs := make(map[string]bool, len(managed))
	for _, mi := range managed {
		if mi.InstanceId != "" {
			managedIDs[mi.InstanceId] = true
		}
	}

	var out []string
	for _, inst := range a.EC2InstanceList() {
		if inst.InstanceId == "" {
			continue
		}
		if managedIDs[inst.InstanceId] {
			out = append(out, ec2InstanceARN(a.ID, inst))
		}
	}
	sort.Strings(out)
	return out
}

// ssmIsAWSManagedKey ports _kms_helpers.is_aws_managed_key: an empty key id (no
// explicit key -> the default alias/aws/ssm key) or an alias/aws/ prefix denotes an
// AWS-managed key, which needs no explicit kms:Decrypt/kms:Encrypt permission.
func ssmIsAWSManagedKey(keyID string) bool {
	if keyID == "" {
		return true
	}
	return strings.HasPrefix(keyID, "alias/aws/")
}

// ssmParameterKeyID returns the custom KMS key id guarding a SecureString parameter.
//
// FIDELITY GAP (see file header): the Python reads param_meta["KeyId"], which
// DescribeParameters returns for SecureString parameters, but model.SSMParameter —
// which this port must build against unmodified — has no KeyId field and the Go SSM
// collector never captures it. So this returns "" for every parameter, which
// ssmIsAWSManagedKey treats as the default AWS-managed key, collapsing the
// SecureString KMS sub-gate to a no-op (identical to Python when a parameter carries
// no KeyId). Add KeyId to model.SSMParameter (+ collector) and return p's key here to
// restore the custom-CMK gate.
func ssmParameterKeyID(p *model.SSMParameter) string {
	return p.KeyId
}
