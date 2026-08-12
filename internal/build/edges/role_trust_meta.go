package edges

// This file ports the CanPassRoleToService MERGE processor of the
// role_trust_and_federation family, which consolidates per-service PassRole
// constituents into one user-facing edge:
//
//	CanPassRoleToService     AWS_CanPassRoleToService     (traversable)
//
// The family's other merge, CanCreateAndPassAdminRole, together with the shared
// constituent recompute helpers, lives in role_trust_create_pass.go.
//
// In AWSHound these merges consume already-materialised AWS_CanPassRoleVia*
// constituent edges (which the framework then SUPPRESSES). The Go schema has no
// constituent edge kinds — only the merged kinds are emitted — so this port
// recomputes every constituent inline from the store + evaluator and assembles the
// merged edge directly, following the iam_manipulation precedent for cross-family
// composites (recompute, don't emit).
//
// The constituents span several sibling families (EC2 RunInstances, Lambda
// CreateFunction, CloudFormation CreateStack/StackSet, EKS CreateNodegroup, the
// SSM create primitives, and the EC2-instance / Lambda-function traversable
// access edges). Each is recomputed here with the exact gating of its own Python
// processor. The recomputed constituents are NOT emitted as edges (their owning
// families emit them); they exist only to feed the merge, exactly as the
// suppressed wave-0/wave-1 edges do in AWSHound.

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

const roleTrustPassRoleToServiceDesc = "Principal can pass this IAM role to one or more AWS services and assume its " +
	"permissions. The `services` property lists services the role already trusts " +
	"(a direct pass); `services_via_trust_rewrite` lists services reachable only " +
	"by first rewriting the role's trust policy via iam:UpdateAssumeRolePolicy. " +
	"See the `methods` property for the per-service technique and evidence."

// roleTrustPassInst is one recomputed AWS_CanPassRoleVia* constituent instance at
// a (principal, role) pair — the evidence the merge folds into
// AWS_CanPassRoleToService.
type roleTrustPassInst struct {
	principal           string
	role                string
	service             string
	method              string
	edgeKind            string // Python constituent EdgeKind string, for methods.edge_kind
	allowSrc            []string
	passCondJSON        string
	requiresTrustUpdate *bool // nil for native-trust-only (create) paths
	// condBags are the constituent's *_conditions property bags in property-
	// insertion order (pass_role first). The merge flattens + dedups them for the
	// top-level conditions property.
	condBags [][]map[string]any
}

// roleTrustPassMethod is one entry in the merged edge's `methods` JSON array.
// Field order matches the Python dict; RequiresTrustUpdate omits when nil (the
// create paths, which set no requires_trust_update).
type roleTrustPassMethod struct {
	Service             string `json:"service"`
	Method              string `json:"method"`
	EdgeKind            string `json:"edge_kind"`
	AllowSources        string `json:"allow_sources"`
	PassRoleConditions  string `json:"pass_role_conditions"`
	RequiresTrustUpdate *bool  `json:"requires_trust_update,omitempty"`
}

// roleTrustPassRoleToServiceEdges recomputes every AWS_CanPassRoleVia* constituent
// for the account and merges them per (principal, role) into one traversable
// AWS_CanPassRoleToService edge. Ports CanPassRoleToServiceEdgeProcessor.
func roleTrustPassRoleToServiceEdges(
	pe *eval.PolicyEvaluator,
	acct *store.Account,
	roleARNs, principals []string,
	updateArp map[string]map[string]*eval.PermissionCheckResult,
) []*graph.Edge {
	ec2Trusted := roleTrustRolesTrustingService(acct, "ec2.amazonaws.com")
	lambdaTrusted := roleTrustRolesTrustingService(acct, "lambda.amazonaws.com")
	cfnTrusted := roleTrustRolesTrustingService(acct, "cloudformation.amazonaws.com")
	ssmTrusted := roleTrustRolesTrustingService(acct, "ssm.amazonaws.com")

	stackARNs := stackARNs(acct)
	stackSetARNs := stackSetARNs(acct)
	clusterARNs := acct.EKSClusterARNs()
	instanceARNs, managedARNs, ebsRoot := roleTrustEc2Instances(acct)
	fnARNs := roleTrustLambdaARNs(acct)
	lambdaPatterns := lambdaFutureARNPatterns(acct)

	var insts []roleTrustPassInst
	for _, p := range principals {
		updForP := updateArp[p]

		// -- Native-trust-only (create/define) paths: roles = service-trusting set. --
		if r := roleTrustAllowed(pe, p, "ec2:RunInstances", "*"); r != nil {
			insts = append(insts, roleTrustPassCreateInstances(pe, p, ec2Trusted, "ec2", "RunInstances",
				"AWS_CanPassRoleViaEC2", "ec2.amazonaws.com", r.Conditions, nil)...)
		}
		if r := roleTrustAllowed(pe, p, "ec2:RequestSpotInstances", "*"); r != nil {
			insts = append(insts, roleTrustPassCreateInstances(pe, p, ec2Trusted, "ec2", "RequestSpotInstances",
				"AWS_CanPassRoleViaEC2SpotInstances", "ec2.amazonaws.com", r.Conditions, nil)...)
		}
		if r := roleTrustFirstAllowedPattern(pe, p, "lambda:CreateFunction", lambdaPatterns); r != nil {
			insts = append(insts, roleTrustPassCreateInstances(pe, p, lambdaTrusted, "lambda", "CreateFunction",
				"AWS_CanPassRoleViaLambda", "lambda.amazonaws.com", r.Conditions, nil)...)
		}
		if r := roleTrustAllowed(pe, p, "cloudformation:CreateStack", "*"); r != nil {
			insts = append(insts, roleTrustPassCreateInstances(pe, p, cfnTrusted, "cloudformation", "CreateStack",
				"AWS_CanPassRoleViaCloudFormation", "cloudformation.amazonaws.com", r.Conditions, nil)...)
		}
		if r := roleTrustAllowed(pe, p, "cloudformation:CreateStackSet", "*"); r != nil {
			// CreateStackSet only defines the set; CreateStackInstances deploys it.
			if inst := roleTrustAllowed(pe, p, "cloudformation:CreateStackInstances", "*"); inst != nil {
				insts = append(insts, roleTrustPassCreateInstances(pe, p, cfnTrusted, "cloudformation", "CreateStackSet",
					"AWS_CanPassRoleViaCloudFormationStackSet", "cloudformation.amazonaws.com", r.Conditions,
					[][]map[string]any{inst.Conditions})...)
			}
		}
		if r := roleTrustFirstAllowed(pe, p, "cloudformation:UpdateStackSet", stackSetARNs); r != nil {
			insts = append(insts, roleTrustPassCreateInstances(pe, p, cfnTrusted, "cloudformation", "UpdateStackSet",
				"AWS_CanPassRoleViaCloudFormationStackSetUpdate", "cloudformation.amazonaws.com", r.Conditions, nil)...)
		}
		if len(clusterARNs) > 0 {
			if r := roleTrustFirstAllowed(pe, p, "eks:CreateNodegroup", clusterARNs); r != nil {
				// A node group's instances run under EC2, so the node role is passed
				// to ec2.amazonaws.com and must trust it.
				insts = append(insts, roleTrustPassCreateInstances(pe, p, ec2Trusted, "eks", "CreateNodegroup",
					"AWS_CanPassRoleViaEKSNodeGroup", "ec2.amazonaws.com", r.Conditions, nil)...)
			}
		}

		// -- Native-or-trust-rewrite paths: roles = service-trusting ∪ the
		//    principal's UpdateAssumeRolePolicy targets. --
		if r := roleTrustFirstAllowed(pe, p, "cloudformation:UpdateStack", stackARNs); r != nil {
			insts = append(insts, roleTrustPassUpdateInstances(pe, p, cfnTrusted, updForP, "cloudformation", "UpdateStack",
				"AWS_CanPassRoleViaCloudFormationUpdate", "cloudformation.amazonaws.com",
				[][]map[string]any{r.Conditions})...)
		}
		createDoc := roleTrustAllowed(pe, p, "ssm:CreateDocument", "*")
		createAssoc := roleTrustAllowed(pe, p, "ssm:CreateAssociation", "*")
		if createDoc != nil && createAssoc != nil {
			insts = append(insts, roleTrustPassUpdateInstances(pe, p, ssmTrusted, updForP, "ssm", "CreateAssociation",
				"AWS_CanPassRoleViaSSMAssociation", "ssm.amazonaws.com",
				[][]map[string]any{createDoc.Conditions, createAssoc.Conditions})...)
		}
		if createDoc != nil {
			if startAuto := roleTrustAllowed(pe, p, "ssm:StartAutomationExecution", "*"); startAuto != nil {
				insts = append(insts, roleTrustPassUpdateInstances(pe, p, ssmTrusted, updForP, "ssm", "StartAutomationExecution",
					"AWS_CanPassRoleViaSSMAutomation", "ssm.amazonaws.com",
					[][]map[string]any{createDoc.Conditions, startAuto.Conditions})...)
			}
		}

		// -- Compute-access-gated paths: principal must additionally hold a
		//    traversable-access edge to an EC2 instance / Lambda function. Those
		//    access primitives are single-action IAM checks recomputed here. --
		if assoc := roleTrustEc2AssocMatch(pe, p, instanceARNs); assoc != nil {
			insts = append(insts, roleTrustPassUpdateInstances(pe, p, ec2Trusted, updForP, "ec2", "AssociateIamInstanceProfile",
				"AWS_CanPassRoleViaEC2Association", "ec2.amazonaws.com",
				[][]map[string]any{assoc.Conditions})...)
		}
		if createAssoc != nil && roleTrustEc2AnyAccess(pe, p, instanceARNs, managedARNs, ebsRoot) {
			insts = append(insts, roleTrustPassUpdateInstances(pe, p, ssmTrusted, updForP, "ssm", "CreateAssociation",
				"AWS_CanPassRoleViaSSMAssociationExisting", "ssm.amazonaws.com",
				[][]map[string]any{createAssoc.Conditions})...)
		}
		if cfg := roleTrustLambdaConfigMatch(pe, p, fnARNs); cfg != nil {
			insts = append(insts, roleTrustPassUpdateInstances(pe, p, lambdaTrusted, updForP, "lambda", "UpdateFunctionConfiguration",
				"AWS_CanPassRoleViaLambdaUpdate", "lambda.amazonaws.com",
				[][]map[string]any{cfg.Conditions})...)
		}
	}

	// Group by (principal, role) and merge.
	groups := map[[2]string][]roleTrustPassInst{}
	var order [][2]string
	for _, inst := range insts {
		k := [2]string{inst.principal, inst.role}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], inst)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i][0] != order[j][0] {
			return order[i][0] < order[j][0]
		}
		return order[i][1] < order[j][1]
	})

	var out []*graph.Edge
	for _, k := range order {
		out = append(out, roleTrustMergePassRoleGroup(k[0], k[1], groups[k]))
	}
	return out
}

// roleTrustPassCreateInstances builds constituent instances for a native-trust
// "create/define" PassRole path: the candidate roles are exactly those trusting
// the service, requires_trust_update is unset (nil), and the condition bags are
// [pass_role, service_action, extra...] in that order.
func roleTrustPassCreateInstances(
	pe *eval.PolicyEvaluator,
	principal string,
	trusted map[string]bool,
	service, method, edgeKind, passedTo string,
	serviceActionConds []map[string]any,
	extraBags [][]map[string]any,
) []roleTrustPassInst {
	var out []roleTrustPassInst
	for _, role := range sortedKeys(trusted) {
		grant := roleTrustEvaluatePassRole(pe, principal, role, passedTo)
		if grant == nil {
			continue
		}
		bags := [][]map[string]any{grant.Conditions, serviceActionConds}
		bags = append(bags, extraBags...)
		out = append(out, roleTrustPassInst{
			principal: principal, role: role, service: service, method: method, edgeKind: edgeKind,
			allowSrc: grant.AllowSources, passCondJSON: conditionsJSON(grant.Conditions),
			requiresTrustUpdate: nil, condBags: bags,
		})
	}
	return out
}

// roleTrustPassUpdateInstances builds constituent instances for a
// native-or-trust-rewrite PassRole path: candidate roles are the service-trusting
// set plus the principal's UpdateAssumeRolePolicy targets. A role already
// trusting the service is native (requires_trust_update=false); a role reachable
// only by rewriting its trust policy is requires_trust_update=true and carries the
// update grant's conditions. Condition bags are [pass_role, mid..., update_trust].
func roleTrustPassUpdateInstances(
	pe *eval.PolicyEvaluator,
	principal string,
	trusted map[string]bool,
	updForP map[string]*eval.PermissionCheckResult,
	service, method, edgeKind, passedTo string,
	midBags [][]map[string]any,
) []roleTrustPassInst {
	cand := map[string]bool{}
	for r := range trusted {
		cand[r] = true
	}
	for r := range updForP {
		cand[r] = true
	}

	var out []roleTrustPassInst
	for _, role := range sortedKeys(cand) {
		grant := roleTrustEvaluatePassRole(pe, principal, role, passedTo)
		if grant == nil {
			continue
		}
		var rtu bool
		var updateTrust []map[string]any
		if trusted[role] {
			rtu = false
		} else {
			ures := updForP[role]
			if ures == nil {
				continue
			}
			rtu = true
			updateTrust = ures.Conditions
		}
		bags := make([][]map[string]any, 0, len(midBags)+2)
		bags = append(bags, grant.Conditions)
		bags = append(bags, midBags...)
		bags = append(bags, updateTrust)
		rtuCopy := rtu
		out = append(out, roleTrustPassInst{
			principal: principal, role: role, service: service, method: method, edgeKind: edgeKind,
			allowSrc: grant.AllowSources, passCondJSON: conditionsJSON(grant.Conditions),
			requiresTrustUpdate: &rtuCopy, condBags: bags,
		})
	}
	return out
}

// roleTrustMergePassRoleGroup folds every constituent at a (principal, role) pair
// into one AWS_CanPassRoleToService edge. `services` lists services the role
// already trusts (a direct pass); `services_via_trust_rewrite` lists services
// reachable only by first rewriting the role's trust policy. Ports
// CanPassRoleToServiceEdgeProcessor._merge.
func roleTrustMergePassRoleGroup(principal, role string, cs []roleTrustPassInst) *graph.Edge {
	sort.Slice(cs, func(i, j int) bool { return cs[i].edgeKind < cs[j].edgeKind })

	serviceNative := map[string]bool{}
	var methods []roleTrustPassMethod
	var allSources []string
	srcSeen := map[string]bool{}
	var allConditions []map[string]any
	condSeen := map[string]bool{}

	for _, c := range cs {
		isNative := c.requiresTrustUpdate == nil || !*c.requiresTrustUpdate
		serviceNative[c.service] = serviceNative[c.service] || isNative
		for _, s := range c.allowSrc {
			if s != "" && !srcSeen[s] {
				srcSeen[s] = true
				allSources = append(allSources, s)
			}
		}
		for _, bag := range c.condBags {
			for _, cond := range bag {
				key := roleTrustCanonicalCond(cond)
				if !condSeen[key] {
					condSeen[key] = true
					allConditions = append(allConditions, cond)
				}
			}
		}
		methods = append(methods, roleTrustPassMethod{
			Service:             c.service,
			Method:              c.method,
			EdgeKind:            c.edgeKind,
			AllowSources:        roleTrustJoin(c.allowSrc),
			PassRoleConditions:  c.passCondJSON,
			RequiresTrustUpdate: c.requiresTrustUpdate,
		})
	}

	var native, rewrite []string
	for svc, isN := range serviceNative {
		if isN {
			native = append(native, svc)
		} else {
			rewrite = append(rewrite, svc)
		}
	}
	sort.Strings(native)
	sort.Strings(rewrite)

	e := graph.NewEdge(principal, role, graph.KindCanPassRoleToService)
	e.Set("is_traversable", true)
	e.Set("description", roleTrustPassRoleToServiceDesc)
	e.Set("services", strings.Join(native, ", "))
	e.Set("services_via_trust_rewrite", strings.Join(rewrite, ", "))
	e.Set("has_trust_rewrite_path", len(rewrite) > 0)
	e.Set("methods", roleTrustMarshalJSON(methods))
	e.Set("allow_sources", roleTrustJoin(allSources))
	e.Set("conditions", conditionsJSON(allConditions))
	return e
}
