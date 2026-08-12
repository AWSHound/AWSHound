// This file ports the CanCreateAndPassAdminRole merge of the
// role_trust_and_federation family (core/graph/edges/meta/, the
// CanCreateAndPassAdminRole processor) together with the cross-family constituent
// recompute helpers (store + evaluator only) shared by both role_trust merges. The
// CanPassRoleToService merge and the package's shared merge documentation live in
// role_trust_meta.go.
package edges

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

const roleTrustCreateAndPassAdminRoleDesc = "Principal can create a new IAM role, attach an admin-grade policy, and pass " +
	"it to one or more AWS services to execute as it — effectively account " +
	"takeover. See the `services` and `methods` properties for which services " +
	"and techniques are usable."

// roleTrustCreatePassInst is one recomputed AWS_CanCreateAndPass*AdminRole
// constituent for a principal. All create-role / attach / pass grants are
// identical across a principal's constituents; only the service and its
// service-create grant differ.
type roleTrustCreatePassInst struct {
	service, method, edgeKind string
	createServiceAllowSrc     string
	createRoleAllowSrc        string
	passRoleAllowSrc          string
	attachAllowSrc            string
	attachMethod              string
	conditions                []map[string]any // service + create-role + pass-role + attach, concatenated
}

// roleTrustCreatePassMethod is one entry in the merged edge's `methods` array.
type roleTrustCreatePassMethod struct {
	Service                           string `json:"service"`
	Method                            string `json:"method"`
	EdgeKind                          string `json:"edge_kind"`
	CreateServiceResourceAllowSources string `json:"create_service_resource_allow_sources"`
}

// roleTrustCreateAndPassAdminRoleEdges recomputes each per-service
// CreateAndPass*AdminRole constituent and merges them per principal into one
// traversable AWS_CanCreateAndPassAdminRole edge (principal -> account root).
// Ports CanCreateAndPassAdminRoleEdgeProcessor + the shared
// _create_and_pass_admin_role base. The role does not exist yet, so the trust
// side is satisfied by construction and not checked.
func roleTrustCreateAndPassAdminRoleEdges(
	pe *eval.PolicyEvaluator,
	acct *store.Account,
	principals []string,
	createRoleRes, attachWild, putWild map[string]*eval.PermissionCheckResult,
) []*graph.Edge {
	accountID := acct.ID
	root := accountRootARN(accountID)
	clusterARNs := acct.EKSClusterARNs()
	lambdaPatterns := lambdaFutureARNPatterns(acct)

	type svcDef struct {
		service, method, edgeKind, passedTo, action string
		perCluster                                  bool
	}
	// Declared in constituent-EdgeKind sort order so `first` (the properties the
	// merge carries once) and the methods array are deterministic.
	svcs := []svcDef{
		{"cloudformation", "CreateStack", "AWS_CanCreateAndPassCloudFormationAdminRole", "cloudformation.amazonaws.com", "cloudformation:CreateStack", false},
		{"ec2", "RunInstances", "AWS_CanCreateAndPassEC2AdminRole", "ec2.amazonaws.com", "ec2:RunInstances", false},
		{"eks", "CreateNodegroup", "AWS_CanCreateAndPassEKSNodeGroupAdminRole", "ec2.amazonaws.com", "eks:CreateNodegroup", true},
		{"lambda", "CreateFunction", "AWS_CanCreateAndPassLambdaAdminRole", "lambda.amazonaws.com", "lambda:CreateFunction", false},
	}

	var out []*graph.Edge
	for _, p := range principals {
		cr, ok := createRoleRes[p]
		if !ok {
			continue
		}
		attachRes, attachMethod := roleTrustPickAttach(attachWild, putWild, p)
		if attachRes == nil {
			continue
		}

		var insts []roleTrustCreatePassInst
		for _, sd := range svcs {
			var svcRes *eval.PermissionCheckResult
			if sd.perCluster {
				if len(clusterARNs) == 0 {
					continue
				}
				svcRes = roleTrustFirstAllowed(pe, p, sd.action, clusterARNs)
			} else if sd.action == "lambda:CreateFunction" {
				svcRes = roleTrustFirstAllowedPattern(pe, p, sd.action, lambdaPatterns)
			} else {
				svcRes = roleTrustAllowed(pe, p, sd.action, "*")
			}
			if svcRes == nil {
				continue
			}
			passGrant := roleTrustEvaluatePassRoleWildcard(pe, accountID, p, sd.passedTo)
			if passGrant == nil {
				continue
			}
			// Aggregate conditions: service-action, create-role, pass-role, attach.
			var conds []map[string]any
			conds = append(conds, svcRes.Conditions...)
			conds = append(conds, cr.Conditions...)
			conds = append(conds, passGrant.Conditions...)
			conds = append(conds, attachRes.Conditions...)
			insts = append(insts, roleTrustCreatePassInst{
				service: sd.service, method: sd.method, edgeKind: sd.edgeKind,
				createServiceAllowSrc: roleTrustJoin(svcRes.AllowSources),
				createRoleAllowSrc:    roleTrustJoin(cr.AllowSources),
				passRoleAllowSrc:      roleTrustJoin(passGrant.AllowSources),
				attachAllowSrc:        roleTrustJoin(attachRes.AllowSources),
				attachMethod:          attachMethod,
				conditions:            conds,
			})
		}
		if len(insts) == 0 {
			continue
		}
		out = append(out, roleTrustMergeCreatePassGroup(p, root, insts))
	}
	return out
}

// roleTrustMergeCreatePassGroup folds a principal's CreateAndPass*AdminRole
// constituents into one AWS_CanCreateAndPassAdminRole edge. The create-role /
// pass-role / attach grants are identical across constituents, so they are
// carried once from the first (by EdgeKind) constituent. Ports
// CanCreateAndPassAdminRoleEdgeProcessor._merge.
func roleTrustMergeCreatePassGroup(principal, root string, cs []roleTrustCreatePassInst) *graph.Edge {
	sort.Slice(cs, func(i, j int) bool { return cs[i].edgeKind < cs[j].edgeKind })

	serviceSet := map[string]bool{}
	var methods []roleTrustCreatePassMethod
	var allConditions []map[string]any
	condSeen := map[string]bool{}
	for _, c := range cs {
		serviceSet[c.service] = true
		methods = append(methods, roleTrustCreatePassMethod{
			Service:                           c.service,
			Method:                            c.method,
			EdgeKind:                          c.edgeKind,
			CreateServiceResourceAllowSources: c.createServiceAllowSrc,
		})
		for _, cond := range c.conditions {
			key := roleTrustCanonicalCond(cond)
			if !condSeen[key] {
				condSeen[key] = true
				allConditions = append(allConditions, cond)
			}
		}
	}
	first := cs[0]

	e := graph.NewEdge(principal, root, graph.KindCanCreateAndPassAdminRole)
	e.Set("is_traversable", true)
	e.Set("description", roleTrustCreateAndPassAdminRoleDesc)
	e.Set("services", strings.Join(sortedKeys(serviceSet), ", "))
	e.Set("methods", roleTrustMarshalJSON(methods))
	e.Set("create_role_allow_sources", first.createRoleAllowSrc)
	e.Set("pass_role_allow_sources", first.passRoleAllowSrc)
	e.Set("attach_policy_allow_sources", first.attachAllowSrc)
	e.Set("attach_policy_method", first.attachMethod)
	e.Set("conditions", conditionsJSON(allConditions))
	return e
}

// -------------------------------------------------------------------------
// Recompute helpers for the cross-family constituents (store + evaluator only)
// -------------------------------------------------------------------------

// roleTrustAllowed returns the permission result when the principal is allowed
// action on resource, else nil.
func roleTrustAllowed(pe *eval.PolicyEvaluator, principal, action, resource string) *eval.PermissionCheckResult {
	if r := pe.CanPerformAction(principal, action, resource, nil); r.Allowed {
		return r
	}
	return nil
}

func roleTrustFirstAllowedPattern(pe *eval.PolicyEvaluator, principal, action string, resources []string) *eval.PermissionCheckResult {
	for _, resource := range resources {
		if result := pe.CanPerformActionPattern(principal, action, resource, nil); result.Allowed {
			return result
		}
	}
	return nil
}

// roleTrustFirstAllowed returns the first (in the given, pre-sorted resource
// order) permission result for which the principal is allowed action, else nil.
// Mirrors the resource-scoped wave-0 primitives (UpdateStack/UpdateStackSet on a
// collected stack/StackSet, CreateNodegroup on a cluster) whose per-principal
// dict keeps the first matching resource.
func roleTrustFirstAllowed(pe *eval.PolicyEvaluator, principal, action string, resources []string) *eval.PermissionCheckResult {
	for _, res := range resources {
		if r := pe.CanPerformAction(principal, action, res, nil); r.Allowed {
			return r
		}
	}
	return nil
}

// roleTrustEc2AssocMatch returns the first (sorted) instance the principal can
// ec2:AssociateIamInstanceProfile or ec2:ReplaceIamInstanceProfileAssociation on
// — the self-accessing precondition for the EC2-association PassRole path (either
// action already makes the instance traversable, so the broader access gate is
// implied). Associate is checked before Replace per instance, matching the
// legacy first-match order.
func roleTrustEc2AssocMatch(pe *eval.PolicyEvaluator, principal string, instanceARNs []string) *eval.PermissionCheckResult {
	for _, arn := range instanceARNs {
		if r := pe.CanPerformAction(principal, "ec2:AssociateIamInstanceProfile", arn, nil); r.Allowed {
			return r
		}
		if r := pe.CanPerformAction(principal, "ec2:ReplaceIamInstanceProfileAssociation", arn, nil); r.Allowed {
			return r
		}
	}
	return nil
}

// roleTrustEc2AnyAccess reports whether the principal holds any traversable-access
// edge to an EC2 instance — ec2:Associate/Modify/Replace on an instance,
// ssm:SendCommand/StartSession on an SSM-managed instance, or the four-action
// volume-swap on an EBS-root instance. This is the access gate the
// SSM-association-existing PassRole path requires.
func roleTrustEc2AnyAccess(pe *eval.PolicyEvaluator, principal string, instanceARNs, managedARNs []string, ebsRoot map[string]bool) bool {
	for _, arn := range instanceARNs {
		if pe.CanPerformAction(principal, "ec2:AssociateIamInstanceProfile", arn, nil).Allowed ||
			pe.CanPerformAction(principal, "ec2:ModifyInstanceAttribute", arn, nil).Allowed ||
			pe.CanPerformAction(principal, "ec2:ReplaceIamInstanceProfileAssociation", arn, nil).Allowed {
			return true
		}
	}
	for _, arn := range managedARNs {
		if pe.CanPerformAction(principal, "ssm:SendCommand", arn, nil).Allowed ||
			pe.CanPerformAction(principal, "ssm:StartSession", arn, nil).Allowed {
			return true
		}
	}
	for _, arn := range instanceARNs {
		if !ebsRoot[arn] {
			continue
		}
		if pe.CanPerformAction(principal, "ec2:StopInstances", arn, nil).Allowed &&
			pe.CanPerformAction(principal, "ec2:DetachVolume", arn, nil).Allowed &&
			pe.CanPerformAction(principal, "ec2:AttachVolume", arn, nil).Allowed &&
			pe.CanPerformAction(principal, "ec2:StartInstances", arn, nil).Allowed {
			return true
		}
	}
	return false
}

// roleTrustLambdaConfigMatch returns the first (sorted) function the principal can
// lambda:UpdateFunctionConfiguration on — both the access gate and the
// role-changing action for the Lambda-update PassRole path (config implies
// access), else nil.
func roleTrustLambdaConfigMatch(pe *eval.PolicyEvaluator, principal string, fnARNs []string) *eval.PermissionCheckResult {
	for _, arn := range fnARNs {
		if r := pe.CanPerformAction(principal, "lambda:UpdateFunctionConfiguration", arn, nil); r.Allowed {
			return r
		}
	}
	return nil
}

// roleTrustLambdaARNs returns the account's Lambda function ARNs, sorted.
func roleTrustLambdaARNs(acct *store.Account) []string {
	var out []string
	for _, fn := range acct.LambdaFunctionList() {
		if fn.FunctionArn != "" {
			out = append(out, fn.FunctionArn)
		}
	}
	sort.Strings(out)
	return out
}

// roleTrustEc2Instances returns the account's EC2 instance ARNs (all, and the
// SSM-managed subset) plus the set of instance ARNs with an EBS-backed root
// volume — the inputs the EC2-instance traversable-access gate needs. ARNs are
// synthesized exactly as the store ingest / node builder do.
func roleTrustEc2Instances(acct *store.Account) (instanceARNs, managedARNs []string, ebsRoot map[string]bool) {
	ebsRoot = map[string]bool{}
	managedIDs := map[string]bool{}
	for _, mi := range acct.SSMManagedInstanceList() {
		managedIDs[mi.InstanceId] = true
	}
	for _, inst := range acct.EC2InstanceList() {
		if inst.InstanceId == "" {
			continue
		}
		arn := ec2InstanceARN(acct.ID, inst)
		instanceARNs = append(instanceARNs, arn)
		if hasEBSRoot(inst) {
			ebsRoot[arn] = true
		}
		if managedIDs[inst.InstanceId] {
			managedARNs = append(managedARNs, arn)
		}
	}
	sort.Strings(instanceARNs)
	sort.Strings(managedARNs)
	return instanceARNs, managedARNs, ebsRoot
}

// roleTrustCanonicalCond returns a canonical (sorted-key) JSON encoding of one
// condition record, used only as a dedup key. Go's json.Marshal sorts map keys,
// matching Python's json.dumps(sort_keys=True) dedup semantics.
func roleTrustCanonicalCond(cond map[string]any) string {
	b, err := json.Marshal(cond)
	if err != nil {
		return ""
	}
	return string(b)
}

// roleTrustMarshalJSON compact-marshals v (the methods arrays) to a string, or ""
// on error — the package convention (compact json.Marshal) for JSON-string
// properties.
func roleTrustMarshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
