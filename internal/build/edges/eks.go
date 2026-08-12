// This file ports the EKS attack-path family (core/graph/edges/eks/, plus
// structural/cluster_has_node_group.py — which is registered under the EKS family
// in ALL_EDGE_PROCESSORS, so structural.go leaves it to us). It emits the SEVEN
// EKS edge kinds the Go schema declares:
//
//	ClusterHasNodeGroup               AWS_ClusterHasNodeGroup               cluster    -> node group   (TRAVERSABLE, data-derived)
//	NodeGroupHasRole                  AWS_NodeGroupHasRole                  node group -> node role    (TRAVERSABLE, data-derived)
//	CanAssumeRoleViaIRSA              AWS_CanAssumeRoleViaIRSA              cluster    -> IAM role      (TRAVERSABLE, trust-policy scan)
//	CanAssumeRoleViaPodIdentity       AWS_CanAssumeRoleViaPodIdentity       cluster    -> IAM role      (TRAVERSABLE, data-derived)
//	CanCreateAndAssociateEKSAccessEntry AWS_CanCreateAndAssociateEKSAccessEntry principal -> cluster (TRAVERSABLE, policy eval)
//	CanCreateEKSNodegroup             AWS_CanCreateEKSNodegroup             principal  -> acct root    (non-traversable, policy eval)
//	CanCreateEKSPodIdentityAssociation AWS_CanCreateEKSPodIdentityAssociation principal -> IAM role   (TRAVERSABLE, policy eval)
//
// NOT emitted here — the two Python composites PassRoleViaEKSNodeGroup and
// CanCreateAndPassEKSNodeGroupAdminRole are non-traversable CONSTITUENTS that
// AWSHound folds into — and then SUPPRESSES beneath — the merged
// AWS_CanPassRoleToService / AWS_CanCreateAndPassAdminRole edges. The Go schema has
// no constituent edge kinds for them (only the merged kinds exist in
// graph/kinds.go), and role_trust_meta.go already recomputes both EKS constituents
// inline (eks:CreateNodegroup on a collected cluster -> ec2.amazonaws.com-trusting
// role for CanPassRoleToService, and the create/attach/pass wildcard chain for
// CanCreateAndPassAdminRole) and emits the merged edges. Emitting them here would
// either reference a non-existent kind or double the merged edges, so this family
// stops at the seven primitives the Go schema defines — exactly as cloudformation.go
// stops at its five.
//
// Fidelity notes:
//   - The Go EKS models carry a node group / association's parent cluster by NAME
//     (clusterName), not by ARN. AWSHound denormalises name -> cluster ARN at ingest
//     (ingest_eks builds cluster_name_to_arn from the account's clusters); we rebuild
//     that per-account map (eksClusterNameToARN) so ClusterHasNodeGroup and the Pod
//     Identity edge key off the real cluster ARN. A node group / association whose
//     cluster name does not resolve is dropped — matching the Python's cluster_arn
//     IS NULL exclusion (ClusterHasNodeGroup) and its ingest-time drop (Pod Identity).
//   - NodeGroupHasRole needs no cluster resolution: get_eks_node_group_role_map
//     includes orphan node groups, so any node group with a nodeRole earns the edge.
//   - IRSA is CROSS-ACCOUNT: a role in account A can trust a cluster's OIDC provider
//     in account B (get_role_trust_policies() is called with no account filter). So
//     eksIRSAEdges scans every role in the store against every cluster's issuer. It
//     parses each role's raw trust JSON itself (not eval.Policy) so a sub/aud
//     condition value that was a scalar string serialises as a JSON string and a list
//     as a JSON array — byte-for-byte what the Python json.dumps of the raw value
//     produces (eval.Policy normalises every condition value to a []string, which
//     would turn a scalar sub into a one-element array and diverge).
//   - Principals are users + roles only (get_all_principal_arns excludes groups).
//   - The three policy-evaluated edges evaluate resource-scoped actions against each
//     COLLECTED cluster ARN (never "*"): a principal holding the action with no
//     cluster present produces no edge, matching the Python resource-scoping.
//   - eks:CreateAccessEntry authorises against the cluster; eks:AssociateAccessPolicy
//     against the access-entry resource, which does not exist yet — so a synthetic
//     access-entry ARN is built from the cluster ARN (eksClusterARNToAccessEntryARN)
//     for the second check, exactly as _cluster_arn_to_access_entry_arn does.
//   - Condition properties carry the evaluator's condition list as a compact JSON
//     string, "" when empty — the package convention (json.Marshal, no separators)
//     established by cloudformation.go / kms.go / role_trust.go. The create-nodegroup
//     primitive names its property service_action_conditions; the others name it
//     conditions — matching each Python processor's Properties(...) exactly.
//   - Property insertion order per edge matches each Python Properties(...) kwargs
//     order, and the final slice is sorted by (start, end, kind) for diff-stable
//     output.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// EKS edge descriptions — copied verbatim from the Python processors' _DESCRIPTION
// literals (raw strings so the embedded quotes, single quotes and backslashes stay
// exactly as the Python source produced them).
const (
	eksClusterHasNodeGroupDesc = `A K8s admin on this cluster can schedule pods on any of its node groups. Use nodeSelector to target a specific node group: kubectl run exploit --image=amazonlinux --overrides='{"spec":{"nodeSelector":{"eks.amazonaws.com/nodegroup":"NODE_GROUP"}}}'. From the pod, access the node role credentials via IMDS.`

	eksNodeGroupHasRoleDesc = `1) Obtain K8s access to the parent cluster (e.g. via an EKS access entry). 2) Schedule a pod targeting this node group using nodeSelector: kubectl run exploit --image=amazonlinux --overrides='{"spec":{"nodeSelector":{"eks.amazonaws.com/nodegroup":"NODE_GROUP"}}}'. 3) From within the pod, access the node role credentials via IMDS: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME.`

	eksIRSADesc = `1) Obtain K8s admin access to this cluster. 2) Find the service account annotated with the target role: kubectl get sa -A -o jsonpath='{range .items[?(@.metadata.annotations.eks\.amazonaws\.com/role-arn)]}{.metadata.namespace}/{.metadata.name}: {.metadata.annotations.eks\.amazonaws\.com/role-arn}{"\n"}{end}'. 3) Create a pod using that service account: kubectl run exploit --image=amazonlinux --serviceaccount=SA_NAME -n NAMESPACE. 4) The IRSA webhook injects AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE. 5) From within the pod: aws sts get-caller-identity.`

	eksPodIdentityDesc = `1) Obtain K8s admin access to this cluster. 2) Identify the service account mapped to the target role: aws eks list-pod-identity-associations --cluster-name CLUSTER. 3) Create a pod using that service account: kubectl run exploit --image=amazonlinux --serviceaccount=SA_NAME -n NAMESPACE. 4) The EKS Pod Identity Agent injects role credentials. 5) From within the pod: aws sts get-caller-identity.`

	eksCreateAndAssociateAccessEntryDesc = `1) aws eks create-access-entry --cluster-name CLUSTER --principal-arn YOUR_ARN. 2) aws eks associate-access-policy --cluster-name CLUSTER --principal-arn YOUR_ARN --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy --access-scope type=cluster. 3) aws eks update-kubeconfig --name CLUSTER. 4) kubectl auth can-i '*' '*' (verify cluster admin).`

	eksCreatePodIdentityAssociationDesc = `1) Establish cluster-admin access through an existing EKS access entry or by creating one and associating AmazonEKSClusterAdminPolicy. 2) aws eks create-pod-identity-association --cluster-name CLUSTER --namespace default --service-account exploit-sa --role-arn TARGET_ROLE_ARN (requires iam:PassRole to pods.eks.amazonaws.com). 3) kubectl create serviceaccount exploit-sa. 4) kubectl run exploit --image=amazonlinux --serviceaccount=exploit-sa. 5) The EKS Pod Identity Agent injects role credentials; run aws sts get-caller-identity.`
)

// EKSEdges emits the EKS family's seven edge kinds for the whole store. Data-derived
// edges (ClusterHasNodeGroup, NodeGroupHasRole, CanAssumeRoleViaPodIdentity) and the
// three policy-evaluated edges are computed per account; CanAssumeRoleViaIRSA is
// cross-account (a role may trust another account's cluster OIDC provider) so it
// scans the whole store once. The combined slice is sorted (start, end, kind) for
// stable output.
// eksClusterCandidates returns every account's EKS cluster ARNs, sorted.
func eksClusterCandidates(s *store.Store) []string {
	var out []string
	for _, a := range s.Accounts() {
		out = append(out, a.EKSClusterARNs()...)
	}
	sort.Strings(out)
	return out
}

func EKSEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	if s == nil {
		return nil
	}

	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })

	var out []*graph.Edge
	for _, a := range accounts {
		// Data-derived edges (requires_policy_evaluation == False): emitted even
		// when no evaluator is supplied.
		out = append(out, eksClusterHasNodeGroupEdges(a)...)
		out = append(out, eksNodeGroupHasRoleEdges(a)...)
		out = append(out, eksPodIdentityAssumeEdges(a)...)

		// Policy-evaluated edges: the Python processors return [] when the
		// evaluator is None, so skip them when pe is nil.
		if pe != nil {
			out = append(out, eksCreateNodegroupEdges(a, pe)...)
			out = append(out, eksCreatePodIdentityAssociationEdges(a, pe)...)
		}
	}

	// CreateAndAssociateAccessEntry: cross-resource composite (CreateAccessEntry on
	// the cluster AND AssociateAccessPolicy on the cluster's synthetic access-entry)
	// via the derived-composite driver.
	if pe != nil {
		out = append(out, GenerateDerivedCompositeEdges(s, pe, []CompositeAction{
			{Action: "eks:CreateAccessEntry", Resource: func(c string) (string, bool) { return c, true }},
			{Action: "eks:AssociateAccessPolicy", Resource: eksClusterARNToAccessEntryARN},
		}, eksClusterCandidates, false,
			func(p, clusterARN string, r []*eval.PermissionCheckResult) *graph.Edge {
				create, associate := r[0], r[1]
				allConds := make([]map[string]any, 0, len(create.Conditions)+len(associate.Conditions))
				allConds = append(allConds, create.Conditions...)
				allConds = append(allConds, associate.Conditions...)
				e := graph.NewEdge(p, clusterARN, graph.KindCanCreateAndAssociateEKSAccessEntry)
				e.Set("is_traversable", true)
				e.Set("description", eksCreateAndAssociateAccessEntryDesc)
				e.Set("create_access_entry_allow_sources", strings.Join(create.AllowSources, ", "))
				e.Set("associate_access_policy_allow_sources", strings.Join(associate.AllowSources, ", "))
				e.Set("conditions", conditionsJSON(allConds))
				return e
			})...)
	}

	// IRSA is cross-account, so it scans the whole store at once rather than
	// per-account.
	out = append(out, eksIRSAEdges(accounts)...)

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

// eksClusterHasNodeGroupEdges ports ClusterHasNodeGroupEdgeProcessor: one traversable
// cluster -> node group edge for every node group whose parent cluster resolves. A
// node group whose clusterName does not map to a collected cluster ARN is dropped
// (get_eks_cluster_node_group_map filters cluster_arn IS NOT NULL).
func eksClusterHasNodeGroupEdges(a *store.Account) []*graph.Edge {
	nameToARN := eksClusterNameToARN(a)
	var out []*graph.Edge
	for _, ng := range a.EKSNodeGroupList() {
		if ng.NodegroupArn == "" || ng.ClusterName == "" {
			continue
		}
		clusterARN, ok := nameToARN[ng.ClusterName]
		if !ok {
			continue
		}
		e := graph.NewEdge(clusterARN, ng.NodegroupArn, graph.KindClusterHasNodeGroup)
		e.Set("is_traversable", true)
		e.Set("description", eksClusterHasNodeGroupDesc)
		out = append(out, e)
	}
	return out
}

// eksNodeGroupHasRoleEdges ports NodeGroupHasRoleEdgeProcessor: one traversable node
// group -> node role edge for every node group carrying a nodeRole. No cluster
// resolution is needed — get_eks_node_group_role_map includes orphan node groups.
func eksNodeGroupHasRoleEdges(a *store.Account) []*graph.Edge {
	var out []*graph.Edge
	for _, ng := range a.EKSNodeGroupList() {
		if ng.NodegroupArn == "" || ng.NodeRole == "" {
			continue
		}
		e := graph.NewEdge(ng.NodegroupArn, ng.NodeRole, graph.KindNodeGroupHasRole)
		e.Set("is_traversable", true)
		e.Set("description", eksNodeGroupHasRoleDesc)
		out = append(out, e)
	}
	return out
}

// eksPodIdentityAssumeEdges ports CanAssumeRoleViaPodIdentityEdgeProcessor: one
// traversable cluster -> role edge per DISTINCT (cluster, role) Pod Identity
// association whose cluster resolves and whose roleArn is set. Associations whose
// cluster name does not resolve are dropped — AWSHound drops them at ingest time
// (ingest_eks: `if not cluster_arn: continue`), so the query never returns them.
func eksPodIdentityAssumeEdges(a *store.Account) []*graph.Edge {
	nameToARN := eksClusterNameToARN(a)
	seen := make(map[[2]string]bool)
	var out []*graph.Edge
	for _, assoc := range a.EKSPodIdentityAssociationList() {
		if assoc.RoleArn == "" || assoc.ClusterName == "" {
			continue
		}
		clusterARN, ok := nameToARN[assoc.ClusterName]
		if !ok {
			continue
		}
		key := [2]string{clusterARN, assoc.RoleArn}
		if seen[key] {
			continue
		}
		seen[key] = true
		e := graph.NewEdge(clusterARN, assoc.RoleArn, graph.KindCanAssumeRoleViaPodIdentity)
		e.Set("is_traversable", true)
		e.Set("description", eksPodIdentityDesc)
		out = append(out, e)
	}
	return out
}

// eksCreateAndAssociateAccessEntryEdges ports
// CanCreateAndAssociateEKSAccessEntryEdgeProcessor: a principal that can both
// eks:CreateAccessEntry on a cluster AND eks:AssociateAccessPolicy on that cluster's
// (synthetic) access-entry resource can grant itself K8s cluster admin. Emitted per
// (principal, cluster) that satisfies both checks, with the two grants' allow_sources
// and their concatenated conditions.
func eksCreateAndAssociateAccessEntryEdges(a *store.Account, pe *eval.PolicyEvaluator) []*graph.Edge {
	clusterARNs := a.EKSClusterARNs()
	if len(clusterARNs) == 0 {
		return nil
	}
	principals := principalARNs(a)

	var out []*graph.Edge
	for _, p := range principals {
		for _, clusterARN := range clusterARNs {
			// eks:CreateAccessEntry authorises against the cluster resource.
			create := pe.CanPerformAction(p, "eks:CreateAccessEntry", clusterARN, nil)
			if !create.Allowed {
				continue
			}
			// eks:AssociateAccessPolicy authorises against the access-entry
			// resource, not the cluster. The entry does not exist yet, so build a
			// synthetic access-entry ARN so IAM resource patterns match.
			accessEntryARN, ok := eksClusterARNToAccessEntryARN(clusterARN)
			if !ok {
				continue
			}
			associate := pe.CanPerformAction(p, "eks:AssociateAccessPolicy", accessEntryARN, nil)
			if !associate.Allowed {
				continue
			}

			allConds := make([]map[string]any, 0, len(create.Conditions)+len(associate.Conditions))
			allConds = append(allConds, create.Conditions...)
			allConds = append(allConds, associate.Conditions...)

			e := graph.NewEdge(p, clusterARN, graph.KindCanCreateAndAssociateEKSAccessEntry)
			e.Set("is_traversable", true)
			e.Set("description", eksCreateAndAssociateAccessEntryDesc)
			e.Set("create_access_entry_allow_sources", strings.Join(create.AllowSources, ", "))
			e.Set("associate_access_policy_allow_sources", strings.Join(associate.AllowSources, ", "))
			e.Set("conditions", conditionsJSON(allConds))
			out = append(out, e)
		}
	}
	return out
}

// eksCreateNodegroupEdges ports CanCreateEKSNodegroupEdgeProcessor: one
// non-traversable principal -> account-root edge per principal that can
// eks:CreateNodegroup on at least one COLLECTED cluster. eks:CreateNodegroup
// authorises against the cluster resource and cannot succeed without an existing
// cluster, so it is evaluated per collected cluster ARN (never "*"); the first
// allowed cluster's grant carries the edge's allow_sources / conditions. The Python
// principals_with_action pre-filter is a pure optimisation (it can only drop
// principals CanPerformAction rejects anyway), so looping every principal is
// identical.
func eksCreateNodegroupEdges(a *store.Account, pe *eval.PolicyEvaluator) []*graph.Edge {
	clusterARNs := a.EKSClusterARNs()
	if len(clusterARNs) == 0 {
		return nil
	}
	principals := principalARNs(a)
	accountRoot := "arn:aws:iam::" + a.ID + ":root"

	var out []*graph.Edge
	for _, p := range principals {
		matched := eksFirstAllowedCluster(pe, p, "eks:CreateNodegroup", clusterARNs)
		if matched == nil {
			continue
		}
		e := graph.NewEdge(p, accountRoot, graph.KindCanCreateEKSNodegroup)
		e.Set("is_traversable", false)
		e.Set("allow_sources", strings.Join(matched.AllowSources, ", "))
		e.Set("service_action_conditions", conditionsJSON(matched.Conditions))
		out = append(out, e)
	}
	return out
}

// eksCreatePodIdentityAssociationEdges ports
// CanCreateEKSPodIdentityAssociationEdgeProcessor, corrected for the API's full
// prerequisites. A traversable principal -> role edge requires, on one cluster:
// CreatePodIdentityAssociation, iam:PassRole on the target role for
// pods.eks.amazonaws.com, and evidence that the principal can run the resulting
// service-account pod (an existing cluster-wide admin access policy, or permission
// to create/upgrade its own access entry to cluster admin).
func eksCreatePodIdentityAssociationEdges(a *store.Account, pe *eval.PolicyEvaluator) []*graph.Edge {
	var trustedRoles []string
	for arn, r := range a.Roles {
		if eksRoleTrustsService(r, "pods.eks.amazonaws.com") {
			trustedRoles = append(trustedRoles, arn)
		}
	}
	if len(trustedRoles) == 0 {
		return nil
	}
	sort.Strings(trustedRoles)

	clusterARNs := a.EKSClusterARNs()
	if len(clusterARNs) == 0 {
		return nil
	}
	principals := principalARNs(a)

	var out []*graph.Edge
	for _, p := range principals {
		var matchingClusters []string
		var allSources []string
		var allConds []map[string]any
		var accessMethods []string
		for _, clusterARN := range clusterARNs {
			create := pe.CanPerformAction(p, "eks:CreatePodIdentityAssociation", clusterARN, nil)
			if !create.Allowed {
				continue
			}
			access, ok := eksClusterAdminProof(a, pe, p, clusterARN)
			if !ok {
				continue
			}
			matchingClusters = append(matchingClusters, clusterARN)
			allSources = append(allSources, create.AllowSources...)
			allSources = append(allSources, access.allowSources...)
			allConds = append(allConds, create.Conditions...)
			allConds = append(allConds, access.conditions...)
			accessMethods = append(accessMethods, access.method)
		}
		if len(matchingClusters) == 0 {
			continue
		}
		for _, roleARN := range trustedRoles {
			if p == roleARN {
				continue
			}
			passRole := roleTrustEvaluatePassRole(pe, p, roleARN, "pods.eks.amazonaws.com")
			if passRole == nil {
				continue
			}
			conditions := append([]map[string]any{}, allConds...)
			conditions = append(conditions, passRole.Conditions...)
			sources := append([]string{}, allSources...)
			sources = append(sources, passRole.AllowSources...)
			e := graph.NewEdge(p, roleARN, graph.KindCanCreateEKSPodIdentityAssociation)
			e.Set("is_traversable", true)
			e.Set("description", eksCreatePodIdentityAssociationDesc)
			e.Set("cluster_arns", strings.Join(matchingClusters, ", "))
			e.Set("allow_sources", strings.Join(eksDedupPreserve(sources), ", "))
			e.Set("pass_role_allow_sources", strings.Join(passRole.AllowSources, ", "))
			e.Set("cluster_access_methods", strings.Join(eksDedupPreserve(accessMethods), ", "))
			e.Set("conditions", conditionsJSON(conditions))
			out = append(out, e)
		}
	}
	return out
}

const eksClusterAdminPolicyARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

type eksClusterAdminEvidence struct {
	method       string
	allowSources []string
	conditions   []map[string]any
}

// eksClusterAdminProof establishes that principal can create a pod on cluster.
// An observed cluster-scoped AmazonEKSClusterAdminPolicy is direct evidence. An
// existing non-admin entry can be upgraded with AssociateAccessPolicy; otherwise
// the principal must be able to both create its entry and associate that policy.
func eksClusterAdminProof(a *store.Account, pe *eval.PolicyEvaluator, principal, clusterARN string) (eksClusterAdminEvidence, bool) {
	clusterName := ""
	for _, cluster := range a.EKSClusterList() {
		if cluster.Arn == clusterARN {
			clusterName = cluster.Name
			break
		}
	}
	if clusterName == "" {
		return eksClusterAdminEvidence{}, false
	}

	hasEntry := false
	accessEntryARN := ""
	for _, entry := range a.EKSAccessEntryList() {
		// EKS access policies may only be associated with STANDARD entries.
		if entry.ClusterName != clusterName || entry.PrincipalArn != principal || !strings.EqualFold(entry.Type, "STANDARD") {
			continue
		}
		hasEntry = true
		accessEntryARN = entry.AccessEntryArn
		for _, policy := range entry.AccessPolicies {
			if policy.PolicyArn == eksClusterAdminPolicyARN && strings.EqualFold(policy.AccessScope.Type, "cluster") {
				return eksClusterAdminEvidence{method: "existing_cluster_admin_access_entry"}, true
			}
		}
	}

	if accessEntryARN == "" {
		var ok bool
		accessEntryARN, ok = eksClusterARNToAccessEntryARN(clusterARN)
		if !ok {
			return eksClusterAdminEvidence{}, false
		}
	}
	associateContext := &eval.RequestContext{Values: map[string]string{
		"eks:accessentrytype": "STANDARD",
		"eks:accessscope":     "cluster",
		"eks:clustername":     clusterName,
		"eks:policyarn":       eksClusterAdminPolicyARN,
		"eks:principalarn":    principal,
	}}
	associate := pe.CanPerformAction(principal, "eks:AssociateAccessPolicy", accessEntryARN, associateContext)
	if !associate.Allowed {
		return eksClusterAdminEvidence{}, false
	}
	evidence := eksClusterAdminEvidence{
		method:       "associate_cluster_admin_access_policy",
		allowSources: append([]string{}, associate.AllowSources...),
		conditions:   append([]map[string]any{}, associate.Conditions...),
	}
	if hasEntry {
		return evidence, true
	}
	createContext := &eval.RequestContext{Values: map[string]string{
		"eks:accessentrytype": "STANDARD",
		"eks:clustername":     clusterName,
		"eks:principalarn":    principal,
	}}
	create := pe.CanPerformAction(principal, "eks:CreateAccessEntry", clusterARN, createContext)
	if !create.Allowed {
		return eksClusterAdminEvidence{}, false
	}
	evidence.method = "create_and_associate_cluster_admin_access_entry"
	evidence.allowSources = append(evidence.allowSources, create.AllowSources...)
	evidence.conditions = append(evidence.conditions, create.Conditions...)
	return evidence, true
}

// eksIRSAEdges ports CanAssumeRoleViaIRSAEdgeProcessor across the whole store. For
// every cluster with an OIDC issuer it scans every role's trust policy (in ANY
// account — cross-account IRSA is common) for a Federated principal that references
// the issuer path, emitting a traversable cluster -> role edge carrying any sub/aud
// condition scoping. Each role's raw trust JSON is parsed once.
func eksIRSAEdges(accounts []*store.Account) []*graph.Edge {
	// Parse every role's trust document once (cross-account), sorted by ARN.
	type eksRoleDoc struct {
		arn string
		doc map[string]any
	}
	var roleDocs []eksRoleDoc
	for _, a := range accounts {
		for arn, r := range a.Roles {
			doc := eksParseTrustDocRaw(r.AssumeRolePolicyDocument)
			if doc == nil {
				continue
			}
			roleDocs = append(roleDocs, eksRoleDoc{arn: arn, doc: doc})
		}
	}
	sort.Slice(roleDocs, func(i, j int) bool { return roleDocs[i].arn < roleDocs[j].arn })

	// Every cluster that has an OIDC issuer, cross-account, sorted by ARN.
	type eksClusterIssuer struct {
		arn    string
		issuer string
	}
	var clusters []eksClusterIssuer
	for _, a := range accounts {
		for _, c := range a.EKSClusterList() {
			if c.Identity.Oidc.Issuer == "" {
				continue
			}
			clusters = append(clusters, eksClusterIssuer{arn: c.Arn, issuer: c.Identity.Oidc.Issuer})
		}
	}
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].arn < clusters[j].arn })

	var out []*graph.Edge
	for _, c := range clusters {
		// Trust policies may reference the full URL or an ARN containing the OIDC
		// issuer path, so match on the scheme-stripped path.
		issuerPath := strings.ReplaceAll(c.issuer, "https://", "")
		for _, rd := range roleDocs {
			matched, conds := eksRoleTrustsOIDCIssuer(rd.doc, issuerPath)
			if !matched {
				continue
			}
			e := graph.NewEdge(c.arn, rd.arn, graph.KindCanAssumeRoleViaIRSA)
			e.Set("is_traversable", true)
			e.Set("description", eksIRSADesc)
			e.Set("oidc_issuer", c.issuer)
			e.Set("irsa_subject", eksTruthyJSON(conds.subject))
			e.Set("irsa_subject_operator", conds.subjectOperator)
			e.Set("irsa_audience", eksTruthyJSON(conds.audience))
			e.Set("is_scoped", eksPyTruthy(conds.subject))
			out = append(out, e)
		}
	}
	return out
}
