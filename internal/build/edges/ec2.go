// This file ports the EC2 attack-path family (core/graph/edges/ec2/). It emits one
// principal -> {instance, account} edge for every EC2 capability the IAM policy
// evaluator grants a principal, faithfully reproducing each Python processor's gating
// action, endpoints, traversability, and property set.
//
// Scope. EC2 has no resource policy, so every constituent is strictly WITHIN an
// account: each Python processor runs per account with get_all_principal_arns(account)
// against that account's instances (or the account root for the account-scoped
// RunInstances / RequestSpotInstances primitives). This port preserves that by
// iterating each account's own principals against its own instances — a principal only
// earns EC2 edges to instances in its OWN account. Principals are users + roles only
// (get_all_principal_arns), never groups.
//
// The account-scoped primitives (AWS_CanRunInstances, AWS_CanRequestSpotInstances) are
// evaluated on resource "*" and point principal -> account root, matching the Python
// wave-0 convention; their action conditions live on service_action_conditions (NOT
// conditions) so the pass-role / create-and-pass composites can read them. They survive
// in the graph (the composites consume but never suppress them), so they are
// materialised here.
//
// Instance-scoped constituents (Associate/Replace/Disassociate IAM instance profile,
// ModifyInstanceAttribute, GetPasswordData, TerminateInstances, CreateImage) point
// principal -> instance and carry conditions on `conditions`. CreateSnapshot targets a
// volume ARN in the policy check but points the edge at the owning instance (the
// meaningful target), emitting one edge on the first attached volume the principal can
// snapshot. EC2CanVolumeSwap is the four-action composite (Stop/Detach/Attach/Start on
// an EBS-root instance) and is the only instance-scoped edge besides
// ModifyInstanceAttribute that is traversable.
//
// Not emitted here: AWS_CanPassRoleViaEC2 / AWS_CanPassRoleViaEC2SpotInstances /
// AWS_CanPassRoleViaEC2Association and AWS_CanCreateAndPassEC2AdminRole. The Go schema
// has no per-service kinds for those — they are folded into the merged
// AWS_CanPassRoleToService / AWS_CanCreateAndPassAdminRole edges, which the role_trust
// family owns and recomputes inline (see role_trust_meta.go). Emitting them here would
// double them. The IAM-profile constituents emitted here are exactly what those
// composites' preconditions re-derive, matching the Python docstrings.
//
// Endpoints carry raw ARNs (the colon->underscore id encoding is a terminal concern of
// the emit package); the instance ARN is synthesized identically to the EC2 node
// builder (region defaulting to us-east-1) so every edge connects to a real node, and
// the account-root ARN matches the IAM node builder. The final edge slice is sorted by
// (start, end, kind) for diff-stable output.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// ec2InstanceSpec binds one single-action, instance-scoped EC2 action to its edge kind
// and is_traversable flag. It captures the shape shared by the simplest EC2 processors:
// for each principal, for each instance in the account, emit principal -> instance when
// CanPerformAction(action, instanceArn) is allowed.
type ec2InstanceSpec struct {
	action      string
	kind        graph.EdgeKind
	traversable bool
}

// ec2InstanceSpecs are the single-action, instance-scoped constituents that share the
// identical shape. Only ModifyInstanceAttribute is traversable (it grants user-data
// code execution under the instance's role); the Associate/Replace/Disassociate
// IAM-profile, GetPasswordData, TerminateInstances, and CreateImage edges are
// non-traversable capability/remediation edges. CreateSnapshot (volume-targeted),
// RunInstances / RequestSpotInstances (account-scoped), and VolumeSwap (four-action
// composite) are shaped differently and handled separately below.
var ec2InstanceSpecs = []ec2InstanceSpec{
	{"ec2:AssociateIamInstanceProfile", graph.KindCanAssociateIAMInstanceProfile, false},
	{"ec2:ReplaceIamInstanceProfileAssociation", graph.KindCanReplaceIAMInstanceProfileAssociation, false},
	{"ec2:DisassociateIamInstanceProfile", graph.KindCanDisassociateIAMInstanceProfile, false},
	{"ec2:ModifyInstanceAttribute", graph.KindCanModifyEC2InstanceAttribute, true},
	{"ec2:GetPasswordData", graph.KindCanGetPasswordData, false},
	{"ec2:CreateImage", graph.KindCanCreateImage, false},
}

// ec2AccountSpec binds one account-scoped EC2 create action (evaluated on resource "*")
// to its wave-0 edge kind. Both are emitted principal -> account root, non-traversable,
// with action conditions on service_action_conditions.
type ec2AccountSpec struct {
	action string
	kind   graph.EdgeKind
}

// ec2AccountSpecs are the account-scoped create primitives. Their end node is the AWS
// account root because RunInstances / RequestSpotInstances are resource-"*" actions —
// the same convention the S3 account-level actions and Lambda CreateFunction use.
var ec2AccountSpecs = []ec2AccountSpec{
	{"ec2:RunInstances", graph.KindCanRunInstances},
	{"ec2:RequestSpotInstances", graph.KindCanRequestSpotInstances},
}

// ec2VolumeSwapAction pairs a volume-swap step's property-key prefix with its EC2
// action. The four steps are evaluated in this fixed order (stop, detach, attach,
// start), matching the Python _ACTIONS / _ACTION_KEYS pairing so the aggregated
// `conditions` list and the per-step `<key>_allow_sources` properties are deterministic.
type ec2VolumeSwapAction struct {
	key    string
	action string
}

// ec2VolumeSwapActions are the four permissions VolumeSwap requires on the instance,
// in Stop -> Detach -> Attach -> Start order.
var ec2VolumeSwapActions = []ec2VolumeSwapAction{
	{"stop", "ec2:StopInstances"},
	{"detach", "ec2:DetachVolume"},
	{"attach", "ec2:AttachVolume"},
	{"start", "ec2:StartInstances"},
}

// EC2Edges emits the EC2 family's attack-path edges for the whole store: the
// account-scoped RunInstances / RequestSpotInstances primitives, the instance-scoped
// per-permission constituents (associate/replace/disassociate IAM profile, modify
// attribute, get password data, terminate, create image), the volume-targeted
// CreateSnapshot edge, and the four-action VolumeSwap composite. EC2 has no meta edges.
func EC2Edges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	managedResourceOperators := ec2ManagedResourceOperators(s)

	var out []*graph.Edge

	// Global instance → attached-volume-ARNs map for the volume-scoped CreateSnapshot.
	volumesByInstance := map[string][]string{}
	for _, a := range accounts {
		for inst, vols := range a.EC2InstanceVolumeARNs() {
			volumesByInstance[inst] = vols
		}
	}

	// CreateSnapshot: bespoke endpoint — evaluate ec2:CreateSnapshot against each
	// attached volume ARN (first allow wins), but point the edge at the owning
	// instance. Via the first-allowed driver.
	out = append(out, GenerateFirstAllowedEdges(s, pe, "ec2:CreateSnapshot", ec2InstanceCandidates,
		func(instanceARN string) []string { return volumesByInstance[instanceARN] },
		func(p, instanceARN string, res *eval.PermissionCheckResult) *graph.Edge {
			return permissionEdge(p, instanceARN, graph.KindCanCreateSnapshot, false, res)
		})...)

	// VolumeSwap: four-action same-instance composite (EBS-root instances) via the
	// composite driver; the per-action allow-source properties are built by the
	// callback.
	vsActions := make([]string, len(ec2VolumeSwapActions))
	for i, a := range ec2VolumeSwapActions {
		vsActions[i] = a.action
	}
	out = append(out, GenerateCompositeEdges(s, pe, vsActions, ec2EBSRootInstanceCandidates, false,
		func(principal, instanceARN string, r []*eval.PermissionCheckResult) *graph.Edge {
			e := graph.NewEdge(principal, instanceARN, graph.KindEC2CanVolumeSwap)
			e.Set("is_traversable", true)
			var allConditions []map[string]any
			for i, a := range ec2VolumeSwapActions {
				e.Set(a.key+"_allow_sources", strings.Join(r[i].AllowSources, ", "))
				allConditions = append(allConditions, r[i].Conditions...)
			}
			e.Set("conditions", conditionsJSON(allConditions))
			return e
		})...)

	// Instance-scoped single-action constituents via the shared spec driver (§10).
	// Instances are evicted from the eval universe (§4), so the spec draws
	// candidates from the resource bag (ec2InstanceCandidates) rather than
	// TypeBitmap; the identity evaluation and permissionEdge are otherwise the same.
	for _, spec := range ec2InstanceSpecs {
		out = append(out, GenerateEdges(s, pe, EdgeSpec{
			Action: spec.action, Kind: spec.kind, TargetType: "instance", Traversable: spec.traversable,
			Class: eval.IdentityGoverned, Candidates: ec2InstanceCandidates,
		})...)
	}

	// TerminateInstances evaluates the service-specific managed-resource key.
	// In particular, AmazonEKSServiceRolePolicy only grants termination where
	// ec2:ManagedResourceOperator proves that EKS owns the target.
	out = append(out, GenerateScanEdges(s, ScanSpec{
		Kind:       graph.KindCanTerminateInstances,
		Candidates: ec2InstanceCandidates,
		Eval: func(principal, instanceArn string) EvalResult {
			contextValues := map[string]string{}
			if operator := managedResourceOperators[instanceArn]; operator != "" {
				contextValues["ec2:managedresourceoperator"] = operator
			}
			requestContext := &eval.RequestContext{
				Values:    contextValues,
				KnownKeys: map[string]bool{"ec2:managedresourceoperator": true},
			}
			result := pe.CanPerformAction(principal, "ec2:TerminateInstances", instanceArn, requestContext)
			return EvalResult{
				Allowed: result.Allowed, AllowSources: result.AllowSources, Conditions: result.Conditions,
			}
		},
	})...)

	// Account-scoped primitives (→ account root, service_action_conditions).
	for _, spec := range ec2AccountSpecs {
		out = append(out, GenerateAccountScopedEdges(s, pe, spec.action, spec.kind, "service_action_conditions")...)
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

// ec2ManagedResourceOperators classifies EC2 instances whose Auto Scaling group
// or EKS tags tie them to a collected managed node group. Targets not present in
// the result have a known-absent ec2:ManagedResourceOperator request key.
func ec2ManagedResourceOperators(s *store.Store) map[string]string {
	const eksOperator = "eks.amazonaws.com"

	out := map[string]string{}
	for _, account := range s.Accounts() {
		autoScalingGroups := map[string]bool{}
		nodeGroups := map[string]bool{}
		for _, nodeGroup := range account.EKSNodeGroupList() {
			nodeGroups[nodeGroup.ClusterName+"\x00"+nodeGroup.NodegroupName] = true
			if nodeGroup.Resources == nil {
				continue
			}
			for _, group := range nodeGroup.Resources.AutoScalingGroups {
				if group.Name != "" {
					autoScalingGroups[group.Name] = true
				}
			}
		}
		for _, instance := range account.EC2InstanceList() {
			var autoScalingGroup, clusterName, nodeGroupName string
			for _, tag := range instance.Tags {
				switch tag.Key {
				case "aws:autoscaling:groupName":
					autoScalingGroup = tag.Value
				case "eks:cluster-name":
					clusterName = tag.Value
				case "eks:nodegroup-name":
					nodeGroupName = tag.Value
				}
			}
			managedByAutoScalingGroup := autoScalingGroups[autoScalingGroup]
			managedByNodeGroupTags := nodeGroups[clusterName+"\x00"+nodeGroupName]
			if managedByAutoScalingGroup || (clusterName != "" && nodeGroupName != "" && managedByNodeGroupTags) {
				out[ec2InstanceARN(account.ID, instance)] = eksOperator
			}
		}
	}
	return out
}

// ec2InstanceCandidates enumerates every account's EC2 instance ARNs from the
// resource bag (instances are evicted from the eval universe, §4), sorted.
func ec2InstanceCandidates(s *store.Store) []string {
	var arns []string
	for _, a := range s.Accounts() {
		arns = append(arns, ec2InstanceARNs(a)...)
	}
	sort.Strings(arns)
	return arns
}

// ec2EBSRootInstanceCandidates enumerates every account's EBS-root instance ARNs
// (the VolumeSwap targets), sorted.
func ec2EBSRootInstanceCandidates(s *store.Store) []string {
	var arns []string
	for _, a := range s.Accounts() {
		arns = append(arns, ec2EBSRootInstanceARNs(a)...)
	}
	sort.Strings(arns)
	return arns
}

// ec2AccountEdge builds an account-scoped wave-0 primitive (principal -> account root,
// non-traversable): AWS_CanRunInstances / AWS_CanRequestSpotInstances. Their action
// conditions are carried on service_action_conditions (NOT conditions) so the pass-role
// / create-and-pass composites can read them, matching the Python. Property insertion
// order is is_traversable, allow_sources, service_action_conditions.
func ec2AccountEdge(start, accountRoot string, kind graph.EdgeKind, res *eval.PermissionCheckResult) *graph.Edge {
	e := graph.NewEdge(start, accountRoot, kind)
	e.Set("is_traversable", false)
	e.Set("allow_sources", strings.Join(res.AllowSources, ", "))
	e.Set("service_action_conditions", conditionsJSON(res.Conditions))
	return e
}

// ec2VolumeSwapEdge builds the AWS_EC2CanVolumeSwap composite for one (principal,
// instance) pair, or nil when the principal lacks any of the four required permissions.
// Ported from EC2CanVolumeSwapEdgeProcessor: all of Stop/Detach/Attach/Start on the
// instance ARN must be allowed (evaluation short-circuits on the first denial). The
// edge is traversable; property insertion order is is_traversable,
// stop_allow_sources, detach_allow_sources, attach_allow_sources, start_allow_sources,
// conditions, where conditions is the concatenation (in step order) of every step's
// evaluator conditions.
func ec2VolumeSwapEdge(pe *eval.PolicyEvaluator, principal, instanceARN string) *graph.Edge {
	results := make([]*eval.PermissionCheckResult, len(ec2VolumeSwapActions))
	for i, a := range ec2VolumeSwapActions {
		res := pe.CanPerformAction(principal, a.action, instanceARN, nil)
		if !res.Allowed {
			return nil
		}
		results[i] = res
	}

	e := graph.NewEdge(principal, instanceARN, graph.KindEC2CanVolumeSwap)
	e.Set("is_traversable", true)
	var allConditions []map[string]any
	for i, a := range ec2VolumeSwapActions {
		e.Set(a.key+"_allow_sources", strings.Join(results[i].AllowSources, ", "))
		allConditions = append(allConditions, results[i].Conditions...)
	}
	e.Set("conditions", conditionsJSON(allConditions))
	return e
}

// ec2InstanceARNs returns the account's EC2 instance ARNs, synthesized identically to
// the store ingest / EC2 node builder and ordered by ARN (EC2InstanceList is already
// ARN-sorted), so instance-scoped iteration and output stay diff-stable.
func ec2InstanceARNs(a *store.Account) []string {
	insts := a.EC2InstanceList()
	out := make([]string, 0, len(insts))
	for _, inst := range insts {
		out = append(out, ec2InstanceARN(a.ID, inst))
	}
	return out
}

// ec2EBSRootInstanceARNs returns the ARNs of the account's instances whose root device
// is EBS-backed — the only instances VolumeSwap can target. Ported from
// EC2CanVolumeSwapEdgeProcessor's EBS-root filter. Order follows EC2InstanceList (ARN
// sorted).
func ec2EBSRootInstanceARNs(a *store.Account) []string {
	var out []string
	for _, inst := range a.EC2InstanceList() {
		if inst.InstanceId == "" {
			continue
		}
		if hasEBSRoot(inst) {
			out = append(out, ec2InstanceARN(a.ID, inst))
		}
	}
	return out
}
