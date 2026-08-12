// Package edges turns collected, store-resident AWS data into OpenGraph attack-path
// and structural relationships — the Go port of AWSHound's
// core/graph/edges/* processors. Each family contributes one <Family>Edges function
// that iterates the store and returns the family's *graph.Edge values.
//
// This file ports the STRUCTURAL family (core/graph/edges/structural/): the
// data-derived backbone every attack path attaches to. None of these edges need
// the policy evaluator — they are read directly off collected relationships
// (account containment, policy attachments, group membership, role trust
// documents, compute execution roles, and the org SCP/RCP hierarchy).
//
// The twelve ported processors and their AWS_* edge kinds are:
//
//	Contains            AWS_Contains             (traversable)
//	MemberOf            AWS_MemberOf
//	HasPolicy           AWS_HasPolicy
//	HasMember           AWS_HasMember
//	HasSCP              AWS_HasSCP
//	HasRCP              AWS_HasRCP
//	AttachedTo          AWS_AttachedTo
//	Trusts              AWS_Trusts
//	TrustedBy           AWS_TrustedBy
//	TrustsSAMLProvider  AWS_TrustsSAMLProvider
//	TrustsOIDCProvider  AWS_TrustsOIDCProvider
//	RunsAs              AWS_RunsAs               (traversable)
//
// ClusterHasNodeGroup lives in the same Python directory but is registered under
// the EKS family in ALL_EDGE_PROCESSORS (edges.eks), so it is emitted by the EKS
// family port, not here.
//
// Every emitted edge carries exactly one property, "is_traversable" — the boolean
// from the schema that BHE keys attack-path traversal off — mirroring each Python
// processor's Properties(is_traversable=...). Endpoints and node ids carry raw
// ARNs (the colon->underscore id encoding is a terminal concern of the emit
// package), and each endpoint ARN is synthesized identically to the corresponding
// node builder so every edge connects to a real node.
package edges

import (
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// StructuralEdges emits the structural backbone for every account in the store:
// containment, policy/group attachment, role trust, compute execution roles, and
// the org SCP/RCP hierarchy. The policy evaluator is unused — structural edges are
// derived directly from collected relationships (each Python processor sets
// requires_policy_evaluation = False) — but the parameter is kept so every family
// exposes the uniform <Family>Edges(store, evaluator) signature.
//
// Accounts and per-category endpoints are iterated in sorted order so the output
// is diff-stable regardless of Go map iteration order; the resulting edge set is
// identical to AWSHound's, which the downstream writer dedups by (start,end,kind).
func StructuralEdges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	_ = pe // structural edges need no policy evaluation

	accounts := s.Accounts()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })

	// The org SCP/RCP → account index is a cross-account lookup: SCPs/RCPs are
	// collected onto (and stored on) the management / delegated-admin account, but
	// a HasSCP/HasRCP edge is emitted from every member account the policy targets.
	// Build it once from every account's policies, matching the Python store's
	// _index_organization_data (policy.AccountIds → per-account policy list).
	scpByAccount, rcpByAccount := structuralOrgPolicyIndex(accounts)

	var out []*graph.Edge
	for _, a := range accounts {
		// Emission order follows the structural block of ALL_EDGE_PROCESSORS.
		out = append(out, structuralContains(a)...)
		out = append(out, structuralMemberOf(a)...)
		out = append(out, structuralHasPolicy(a)...)
		out = append(out, structuralHasMember(a)...)
		out = append(out, structuralHasSCP(a, scpByAccount)...)
		out = append(out, structuralHasRCP(a, rcpByAccount)...)
		out = append(out, structuralAttachedTo(a)...)
		out = append(out, structuralTrusts(a)...)
		out = append(out, structuralTrustedBy(a)...)
		out = append(out, structuralTrustsSAMLProvider(a)...)
		out = append(out, structuralTrustsOIDCProvider(a)...)
		out = append(out, structuralRunsAs(a)...)
	}
	return out
}

// structuralContains ports ContainsEdgeProcessor (AWS_Contains, traversable): the
// hierarchical ownership edges from an account root to every principal, own
// (customer-managed) policy, federation provider, and non-IAM resource it
// contains, plus account-to-bucket and bucket-to-object S3 ownership. Every edge
// is traversable.
func structuralContains(a *store.Account) []*graph.Edge {
	accountID := a.ID
	accountArn := accountRootARN(accountID)
	var out []*graph.Edge

	// Account -> Users / Groups / Roles.
	for _, arn := range sortedKeys(a.Users) {
		out = structuralAppend(out, accountArn, a.Users[arn].Arn, graph.KindContains, true)
	}
	for _, arn := range sortedKeys(a.Groups) {
		out = structuralAppend(out, accountArn, a.Groups[arn].Arn, graph.KindContains, true)
	}
	for _, arn := range sortedKeys(a.Roles) {
		out = structuralAppend(out, accountArn, a.Roles[arn].Arn, graph.KindContains, true)
	}

	// Account -> customer-managed policies only. AWS-managed policies
	// (arn:aws:iam::aws:policy/...) are owned by AWS, not this account, so they are
	// excluded — emitting Contains for them would explode the edge count without
	// representing real ownership.
	ownPolicyPrefix := "arn:aws:iam::" + accountID + ":policy/"
	for _, arn := range sortedKeys(a.ManagedPolicies) {
		policyArn := a.ManagedPolicies[arn].Arn
		if !strings.HasPrefix(policyArn, ownPolicyPrefix) {
			continue
		}
		out = structuralAppend(out, accountArn, policyArn, graph.KindContains, true)
	}

	// Account -> enumerated SAML / OIDC federation providers (always same-account).
	for _, arn := range sortedKeys(a.SAMLProviders) {
		out = structuralAppend(out, accountArn, arn, graph.KindContains, true)
	}
	for _, arn := range sortedKeys(a.OIDCProviders) {
		out = structuralAppend(out, accountArn, arn, graph.KindContains, true)
	}

	// Account -> EC2 instances (ARN synthesized exactly as the EC2 node builder).
	for _, inst := range a.EC2InstanceList() {
		if inst.InstanceId == "" {
			continue
		}
		out = structuralAppend(out, accountArn, ec2InstanceARN(accountID, inst), graph.KindContains, true)
	}

	// Account -> KMS keys.
	for _, key := range a.KMSKeyList() {
		out = structuralAppend(out, accountArn, key.Arn, graph.KindContains, true)
	}

	// Account -> SSM parameters. The Python skips parameters with no Name; the ARN
	// is the parameter's own ARN, falling back to the synthesized form the node
	// builder / store ingest use.
	for _, p := range a.SSMParameterList() {
		if p.Name == "" {
			continue
		}
		out = structuralAppend(out, accountArn, structuralSSMParameterARN(accountID, p), graph.KindContains, true)
	}

	// Account -> Lambda functions.
	for _, fn := range a.LambdaFunctionList() {
		out = structuralAppend(out, accountArn, fn.FunctionArn, graph.KindContains, true)
	}

	// Account -> CloudFormation stacks and StackSets.
	for _, stack := range a.CloudFormationStackList() {
		out = structuralAppend(out, accountArn, stack.StackId, graph.KindContains, true)
	}
	for _, ss := range a.CloudFormationStackSetList() {
		out = structuralAppend(out, accountArn, ss.StackSetARN, graph.KindContains, true)
	}

	// Account -> EKS clusters and node groups.
	for _, c := range a.EKSClusterList() {
		out = structuralAppend(out, accountArn, c.Arn, graph.KindContains, true)
	}
	for _, ng := range a.EKSNodeGroupList() {
		out = structuralAppend(out, accountArn, ng.NodegroupArn, graph.KindContains, true)
	}

	// Account -> S3 bucket -> objects. Bucket ARN falls back to
	// arn:aws:s3:::<name> (matching the S3 node builder); object ARN is
	// arn:aws:s3:::<name>/<key>.
	buckets := a.S3BucketList()
	sort.Slice(buckets, func(i, j int) bool { return bucketARN(buckets[i]) < bucketARN(buckets[j]) })
	for _, b := range buckets {
		if b.Name == "" {
			continue
		}
		bucketArn := bucketARN(b)
		out = structuralAppend(out, accountArn, bucketArn, graph.KindContains, true)
		objects := append([]model.S3Object(nil), b.Objects...)
		sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
		for _, obj := range objects {
			if obj.Key == "" {
				continue
			}
			out = structuralAppend(out, bucketArn, "arn:aws:s3:::"+b.Name+"/"+obj.Key, graph.KindContains, true)
		}
	}

	return out
}

// structuralHasPolicy ports HasPolicyEdgeProcessor (AWS_HasPolicy, non-traversable):
// principal -> attached managed policy, for users, groups, and roles.
func structuralHasPolicy(a *store.Account) []*graph.Edge {
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Users) {
		u := a.Users[arn]
		for i := range u.AttachedManagedPols {
			out = structuralAppend(out, u.Arn, u.AttachedManagedPols[i].PolicyArn, graph.KindHasPolicy, false)
		}
	}
	for _, arn := range sortedKeys(a.Groups) {
		g := a.Groups[arn]
		for i := range g.AttachedManagedPols {
			out = structuralAppend(out, g.Arn, g.AttachedManagedPols[i].PolicyArn, graph.KindHasPolicy, false)
		}
	}
	for _, arn := range sortedKeys(a.Roles) {
		r := a.Roles[arn]
		for i := range r.AttachedManagedPols {
			out = structuralAppend(out, r.Arn, r.AttachedManagedPols[i].PolicyArn, graph.KindHasPolicy, false)
		}
	}
	return out
}

// structuralAttachedTo ports AttachedToEdgeProcessor (AWS_AttachedTo,
// non-traversable): the inverse of HasPolicy — managed policy -> principal.
func structuralAttachedTo(a *store.Account) []*graph.Edge {
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Users) {
		u := a.Users[arn]
		for i := range u.AttachedManagedPols {
			out = structuralAppend(out, u.AttachedManagedPols[i].PolicyArn, u.Arn, graph.KindAttachedTo, false)
		}
	}
	for _, arn := range sortedKeys(a.Groups) {
		g := a.Groups[arn]
		for i := range g.AttachedManagedPols {
			out = structuralAppend(out, g.AttachedManagedPols[i].PolicyArn, g.Arn, graph.KindAttachedTo, false)
		}
	}
	for _, arn := range sortedKeys(a.Roles) {
		r := a.Roles[arn]
		for i := range r.AttachedManagedPols {
			out = structuralAppend(out, r.AttachedManagedPols[i].PolicyArn, r.Arn, graph.KindAttachedTo, false)
		}
	}
	return out
}

// structuralMemberOf ports MemberOfEdgeProcessor (AWS_MemberOf, non-traversable):
// user -> group, one edge per entry in the user's GroupList. The group ARN is
// synthesized from the account id and group name, matching the Python.
func structuralMemberOf(a *store.Account) []*graph.Edge {
	accountID := a.ID
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Users) {
		u := a.Users[arn]
		for _, groupName := range u.GroupList {
			groupArn := "arn:aws:iam::" + accountID + ":group/" + groupName
			out = structuralAppend(out, u.Arn, groupArn, graph.KindMemberOf, false)
		}
	}
	return out
}

// structuralHasMember ports HasMemberEdgeProcessor (AWS_HasMember,
// non-traversable): the inverse of MemberOf — group -> user, derived from each
// user's GroupList.
func structuralHasMember(a *store.Account) []*graph.Edge {
	accountID := a.ID
	var out []*graph.Edge
	for _, arn := range sortedKeys(a.Users) {
		u := a.Users[arn]
		for _, groupName := range u.GroupList {
			groupArn := "arn:aws:iam::" + accountID + ":group/" + groupName
			out = structuralAppend(out, groupArn, u.Arn, graph.KindHasMember, false)
		}
	}
	return out
}

// structuralAppend appends a graph edge start-(kind)->end carrying the single
// is_traversable property, skipping the (real-data-impossible) empty-endpoint case
// so a malformed ARN never panics graph.NewEdge and aborts the whole build.
func structuralAppend(out []*graph.Edge, start, end string, kind graph.EdgeKind, traversable bool) []*graph.Edge {
	if start == "" || end == "" {
		return out
	}
	return append(out, graph.NewEdge(start, end, kind).Set("is_traversable", traversable))
}

// structuralSSMParameterARN returns a parameter's ARN, falling back to the
// synthesized arn:aws:ssm:<region>:<account>:parameter<name> the store ingest and
// SSM node builder use (region defaulting to us-east-1) when the stored ARN is
// empty — so the Contains edge always matches the parameter node id.
func structuralSSMParameterARN(accountID string, p *model.SSMParameter) string {
	if p.ARN != "" {
		return p.ARN
	}
	region := p.Region
	if region == "" {
		region = "us-east-1"
	}
	return "arn:aws:ssm:" + region + ":" + accountID + ":parameter" + p.Name
}
