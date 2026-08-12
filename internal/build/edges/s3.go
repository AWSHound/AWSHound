// This file ports the S3 attack-path family (core/graph/edges/s3/) plus the S3
// Read/Write/All meta edges (core/graph/edges/meta/, see s3_meta.go). It emits
// principal -> {bucket, object, account} edges for every s3:* capability the IAM
// policy evaluator grants, then consolidates them into the six S3 meta edges.
//
// Branch fidelity. Each Python S3 processor has two evaluation paths: an
// S3PolicyEvaluator path (IAM + bucket policy + ACL + Block-Public-Access) and an
// IAM-only fallback (policy_evaluator.can_perform_action). The bucket- and
// object-scoped processors take the S3PolicyEvaluator path, so — like
// runtime.contexts.build_s3_context — this port builds an eval.S3Evaluator from
// every account's bucket policies/ACLs/Block-Public-Access and gates those edges
// through EvaluateS3Access. That composes the identity side with the bucket's own
// resource controls: same-account = IAM OR bucket policy OR ACL; cross-account =
// IAM AND bucket policy (or an independent ACL grant); an explicit deny on any
// layer wins; Block Public Access can clip a public bucket. Bucket policies are
// PLAIN JSON (parsed via eval.ParseResourcePolicy, NOT ParsePolicyDocument, which
// url-unescapes). The two account-level processors (ListAllMyBuckets,
// PutAccountPublicAccessBlock) are IAM-only in AWSHound, so they stay on
// CanPerformAction. Edge allow_sources/conditions come from whichever evaluator
// gated the edge (on the composed path the S3-layer labels "iam_policy" /
// "bucket_policy" / "acl"), mirroring the Python. The per-object wildcard
// optimization in the *ObjectAcl processors is preserved (independent of which
// evaluator is used).
//
// Global context. Like runtime.contexts.build_s3_context, buckets and objects are
// aggregated across EVERY account before evaluation, so a principal in account A
// can receive an S3 edge to a bucket/object in account B whenever its identity
// policy allows the action on that resource. Objects-collected is a global
// predicate: if any bucket in the org has objects, every object-family processor
// targets individual objects; if none do, they fall back to bucket-level edges
// (resource "<bucket>/*", endpoint the bucket node). Account-level actions
// (ListAllMyBuckets, PutAccountPublicAccessBlock) target the principal's own
// AWS_Account node.
//
// Principals are users + roles only (get_all_principal_arns), never groups.
// Endpoints and node ids carry raw ARNs (the colon->underscore id encoding is a
// terminal concern of the emit package); each is synthesized identically to the
// S3/IAM node builders so every edge connects to a real node. The final edge slice
// is sorted by (start, end, kind) for diff-stable output.
package edges

import (
	"container/heap"
	"encoding/json"
	"sort"
	"strings"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// s3WildcardResource is the resource ARN the account-level S3 actions evaluate
// against — matching each Python processor's `s3_wildcard_resource`.
const s3WildcardResource = "arn:aws:s3:::*"

// s3SimpleBucketActions are the bucket-scoped control-plane actions whose Python
// processors share the identical shape: for each principal, for each bucket, emit
// principal -> bucket when CanPerformAction(action, bucket_arn) is allowed. The
// resource is the bucket ARN itself (not "<bucket>/*").
var s3SimpleBucketActions = []struct {
	action string
	kind   graph.EdgeKind
	bit    uint64
}{
	{"s3:ListBucket", graph.KindCanListBucket, s3BitListBucket},
	{"s3:GetBucketAcl", graph.KindCanGetBucketACL, s3BitGetBucketACL},
	{"s3:PutBucketAcl", graph.KindCanPutBucketACL, s3BitPutBucketACL},
	{"s3:GetBucketPolicy", graph.KindCanGetBucketPolicy, s3BitGetBucketPolicy},
	{"s3:PutBucketPolicy", graph.KindCanPutBucketPolicy, s3BitPutBucketPolicy},
	{"s3:DeleteBucketPolicy", graph.KindCanDeleteBucketPolicy, s3BitDeleteBucketPolicy},
	{"s3:DeleteBucket", graph.KindCanDeleteBucket, s3BitDeleteBucket},
	{"s3:PutBucketPublicAccessBlock", graph.KindCanPutBucketPublicAccessBlock, s3BitPutBucketPAB},
	{"s3:PutBucketOwnershipControls", graph.KindCanPutBucketOwnershipControls, s3BitPutBucketOwnership},
}

const (
	s3BitListBucket uint64 = 1 << iota
	s3BitGetBucketACL
	s3BitPutBucketACL
	s3BitGetBucketPolicy
	s3BitPutBucketPolicy
	s3BitDeleteBucketPolicy
	s3BitDeleteBucket
	s3BitPutBucketPAB
	s3BitPutBucketOwnership
	s3BitGetObject
	s3BitDeleteObject
	s3BitPutObject
	s3BitGetObjectACL
	s3BitPutObjectACL
)

const s3ObjectActionMask = s3BitGetObject | s3BitDeleteObject | s3BitPutObject | s3BitGetObjectACL | s3BitPutObjectACL

var s3TargetActions = []string{
	"s3:ListBucket", "s3:GetBucketAcl", "s3:PutBucketAcl",
	"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
	"s3:DeleteBucket", "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls",
	"s3:GetObject", "s3:DeleteObject", "s3:PutObject", "s3:GetObjectAcl", "s3:PutObjectAcl",
}

// s3StreamBucket is the stable per-bucket state needed while merging selected
// buckets' sorted target lists. objectCount is used only to decide whether the ACL
// wildcard shortcut should be warmed for this bucket.
type s3StreamBucket struct {
	arn           string
	ownerAccount  string
	objectCount   int
	targets       []s3StreamTarget
	hasPolicy     bool
	publicACLMask uint64
}

// s3StreamTarget is one bucket or object endpoint in global ARN order. Keeping a
// compact target list is intentional: it costs one small record per displayed S3
// resource, while the old implementation cost several full graph.Edge objects
// per ALLOWED (principal, resource, action) tuple.
type s3StreamTarget struct {
	arn       string
	bucketIdx int
	isObject  bool
}

// s3StreamContext is read-only after construction and shared across every
// principal's pair-local walk.
type s3StreamContext struct {
	buckets           []s3StreamBucket
	bucketsByOwner    map[string][]int
	policyByOwner     map[string][]int
	policyByPrincipal map[string][]int
	policyByAccount   map[string][]int
	policyForAll      []int
	policyDynamic     []int
	publicACLBuckets  []int
	rootByPrincipal   map[string]string
	hasObjects        bool
	evaluator         *eval.S3Evaluator
}

// newS3StreamContext builds the global S3 resource-policy context and a sorted,
// lightweight endpoint list. Bucket names are globally unique; on duplicate
// collection the first account in deterministic account order wins, matching the
// previous S3Edges implementation.
func newS3StreamContext(s *store.Store, pe *eval.PolicyEvaluator) *s3StreamContext {
	accounts := s.Accounts()

	// Global S3 context: bucket ARNs (and their object ARNs) from every account. A
	// bucket must have a name to have a node, so nameless buckets are skipped to
	// avoid dangling endpoints; object ARNs use the bucket name (matching the node
	// builder's arn:aws:s3:::<name>/<key>).
	//
	// The same sweep builds the resource-control context the S3 evaluator composes
	// with the identity side (mirroring runtime.contexts.build_s3_context): a
	// per-bucket eval.S3BucketConfig — its bucket policy parsed as PLAIN JSON via
	// eval.ParseResourcePolicy, its ACL, per-bucket Block Public Access, ownership
	// controls, and owning account — keyed by bucket ARN, plus each account's
	// account-level Block Public Access keyed by account id.
	ctx := &s3StreamContext{
		rootByPrincipal:   make(map[string]string),
		bucketsByOwner:    make(map[string][]int),
		policyByOwner:     make(map[string][]int),
		policyByPrincipal: make(map[string][]int),
		policyByAccount:   make(map[string][]int),
	}
	seen := make(map[string]bool)
	bucketConfigs := make(map[string]*eval.S3BucketConfig)
	accountPABs := make(map[string]*eval.PublicAccessBlock)
	for _, a := range accounts {
		for _, principal := range principalARNs(a) {
			ctx.rootByPrincipal[principal] = accountRootARN(a.ID)
		}
		if pab := s3EvalPAB(a.S3AccountPublicAccessBlock()); pab != nil {
			accountPABs[a.ID] = pab
		}
		for _, b := range a.S3BucketList() {
			if b.Name == "" {
				continue
			}
			arn := bucketARN(b)
			if seen[arn] {
				continue
			}
			seen[arn] = true
			bucketIdx := len(ctx.buckets)
			parsedPolicy := s3EvalBucketPolicy(b.BucketPolicy)
			ctx.buckets = append(ctx.buckets, s3StreamBucket{
				arn:          arn,
				ownerAccount: a.ID,
				hasPolicy:    parsedPolicy != nil,
			})
			ctx.bucketsByOwner[a.ID] = append(ctx.bucketsByOwner[a.ID], bucketIdx)
			ctx.buckets[bucketIdx].targets = append(ctx.buckets[bucketIdx].targets,
				s3StreamTarget{arn: arn, bucketIdx: bucketIdx})
			indexS3PolicyPrincipals(ctx, parsedPolicy, bucketIdx)
			bucketConfigs[arn] = &eval.S3BucketConfig{
				BucketArn:         arn,
				BucketPolicy:      parsedPolicy,
				ACL:               s3EvalACL(b.Acl),
				BlockPublicAccess: s3EvalPAB(b.PublicAccessBlock),
				OwnershipControls: b.OwnershipControls,
				OwnerAccountID:    a.ID,
			}

			for i := range b.Objects {
				key := b.Objects[i].Key
				if key == "" {
					continue
				}
				ctx.buckets[bucketIdx].objectCount++
				ctx.hasObjects = true
				ctx.buckets[bucketIdx].targets = append(ctx.buckets[bucketIdx].targets, s3StreamTarget{
					arn:       "arn:aws:s3:::" + b.Name + "/" + key,
					bucketIdx: bucketIdx,
					isObject:  true,
				})
			}
		}
	}
	// The S3 evaluator composes the identity side (wrapped via iamIdentity, since
	// pe.CanPerformAction carries an extra request-context argument) with each
	// bucket's resource controls. It is used for every bucket-/object-scoped action;
	// the account-level actions below stay IAM-only, matching AWSHound.
	ctx.evaluator = eval.NewS3Evaluator(iamIdentity(pe), bucketConfigs, accountPABs, pe.ResourcePolicyContext)
	for i := range ctx.buckets {
		b := &ctx.buckets[i]
		sort.Slice(b.targets, func(i, j int) bool { return s3TargetLess(&b.targets[i], &b.targets[j]) })
		if b.hasPolicy {
			ctx.policyByOwner[b.ownerAccount] = append(ctx.policyByOwner[b.ownerAccount], i)
		}
		b.publicACLMask = ctx.evaluator.BucketACLMayAllowMask(b.arn, s3TargetActions)
		if b.publicACLMask != 0 {
			ctx.publicACLBuckets = append(ctx.publicACLBuckets, i)
		}
	}
	return ctx
}

// indexS3PolicyPrincipals splits bucket-policy Allows by their cheapest sound
// principal selector. Exact IAM ARNs and account principals are point lookups;
// only glob/NotPrincipal/unusual principal blocks need the dynamic fallback.
// The final bucket-policy evaluator still binds actions, resources and
// conditions, so these lists are conservative hints rather than decisions.
func indexS3PolicyPrincipals(ctx *s3StreamContext, policy *eval.Policy, bucketIdx int) {
	if policy == nil {
		return
	}
	exact := make(map[string]bool)
	accounts := make(map[string]bool)
	forAll, dynamic := false, false
	for i := range policy.Statements {
		st := &policy.Statements[i]
		// checkBucketPolicy ignores NotAction, so a statement without Action can
		// never grant one of this builder's action queries.
		if st.Effect != "Allow" || len(st.Action) == 0 {
			continue
		}
		if st.NotPrincipal != nil {
			dynamic = true
		}
		p := st.Principal
		if p == nil {
			continue
		}
		if p.Wildcard {
			forAll = true
		}
		// StreamS3Edges evaluates stored users/roles, for which the shared
		// principal matcher consults only AWS entries. Service, federated and
		// canonical-user entries therefore cannot add a candidate here.
		for _, entry := range p.AWS {
			switch {
			case entry == "*":
				forAll = true
			case strings.HasSuffix(entry, ":root"):
				parts := strings.Split(entry, ":")
				if len(parts) >= 5 && parts[4] != "" {
					accounts[parts[4]] = true
				}
			case isS3AccountPrincipal(entry):
				accounts[entry] = true
			case strings.ContainsAny(entry, "*?"):
				dynamic = true
			default:
				exact[entry] = true
			}
		}
	}
	if forAll {
		ctx.policyForAll = append(ctx.policyForAll, bucketIdx)
	}
	if dynamic {
		ctx.policyDynamic = append(ctx.policyDynamic, bucketIdx)
	}
	for principal := range exact {
		ctx.policyByPrincipal[principal] = append(ctx.policyByPrincipal[principal], bucketIdx)
	}
	for account := range accounts {
		ctx.policyByAccount[account] = append(ctx.policyByAccount[account], bucketIdx)
	}
}

func isS3AccountPrincipal(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// S3Edges is the compatibility, accumulating API used by AllEdges and direct
// callers. The CLI's StreamEdges path calls StreamS3Edges directly, so production
// builds never materialize the family-wide slice.
func S3Edges(s *store.Store, pe *eval.PolicyEvaluator) []*graph.Edge {
	var out []*graph.Edge
	StreamS3Edges(s, pe, func(e *graph.Edge) { out = append(out, e) })
	return out
}

// StreamS3Edges evaluates and consolidates exactly one (principal, target) pair
// at a time, emitting the final sorted edges before moving on. Meta-edge waves
// and suppression are pair-local by definition, so this is byte-equivalent to
// building the org-wide constituent set while bounding live edge memory to the
// small number of S3 kinds that can exist at one pair.
func StreamS3Edges(s *store.Store, pe *eval.PolicyEvaluator, emit func(*graph.Edge)) {
	StreamS3EdgesProgress(s, pe, func() {}, emit)
}

// StreamS3EdgesProgress is StreamS3Edges with one completion tick per principal.
func StreamS3EdgesProgress(s *store.Store, pe *eval.PolicyEvaluator, onPrincipal func(), emit func(*graph.Edge)) {
	ctx := newS3StreamContext(s, pe)
	identityMasks := pe.PrincipalActionMasksAnyResource(s3TargetActions)
	selected := make([]uint64, len(ctx.buckets))
	for _, principal := range allPrincipals(s) {
		// Account-level S3 actions sort before S3 endpoints because their target is
		// the principal's arn:aws:iam account root.
		root := ctx.rootByPrincipal[principal]
		var rootPair map[graph.EdgeKind]*graph.Edge
		for _, spec := range []struct {
			action string
			kind   graph.EdgeKind
		}{
			{"s3:ListAllMyBuckets", graph.KindCanListAllMyBuckets},
			{"s3:PutAccountPublicAccessBlock", graph.KindCanPutAccountPublicAccessBlock},
		} {
			if e := s3AccountLevelEdge(pe, principal, root, spec.action, spec.kind); e != nil {
				rootPair = s3PutPairEdge(rootPair, e)
			}
		}
		emitS3Pair(rootPair, emit)

		var identityMask uint64
		if id, ok := s.ARN().ID(principal); ok {
			identityMask = identityMasks[id]
		}
		candidateBuckets := ctx.candidateBuckets(principal, identityMask, selected[:])

		// The ACL wildcard optimization is per principal and bucket. Cache only
		// those two results; PutObject still evaluates every object exactly as the
		// original processor did.
		wildcards := make(map[int]s3ACLWildcards)

		var previous *s3StreamTarget
		walk := newS3TargetHeap(ctx, candidateBuckets)
		for walk.Len() > 0 {
			cursor := heap.Pop(walk).(*s3TargetCursor)
			target := &cursor.targets[cursor.pos]
			cursor.pos++
			if cursor.pos < len(cursor.targets) {
				heap.Push(walk, cursor)
			}
			// Duplicate object keys previously collapsed in s3ApplyMetaWaves' pair
			// map. Collapse them here before evaluation and emission instead.
			if previous != nil && previous.arn == target.arn && previous.isObject == target.isObject {
				continue
			}
			previous = target

			bucket := &ctx.buckets[target.bucketIdx]
			candidateMask := selected[target.bucketIdx]
			if !target.isObject {
				pair := s3BucketPair(ctx, principal, bucket, candidateMask)
				if ctx.hasObjects && bucket.objectCount > 0 {
					wildcards[target.bucketIdx] = s3ACLWildcardResults(ctx, principal, bucket, candidateMask)
				}
				emitS3Pair(pair, emit)
				continue
			}

			// A bucket ARN is a strict prefix of each object ARN, so the globally
			// sorted target walk always visits it first. Retain a defensive lazy
			// path for malformed/custom ARNs that violate that ordering assumption.
			aclWildcards, ready := wildcards[target.bucketIdx]
			if !ready {
				aclWildcards = s3ACLWildcardResults(ctx, principal, bucket, candidateMask)
				wildcards[target.bucketIdx] = aclWildcards
			}
			objectMask := candidateMask & s3ObjectActionMask
			if objectMask == s3BitGetObjectACL && aclWildcards.get.Allowed {
				emit(s3ConstituentEdge(principal, target.arn, graph.KindCanGetObjectACL,
					aclWildcards.get.AllowSources, aclWildcards.get.Conditions))
				continue
			}
			if objectMask == s3BitPutObjectACL && aclWildcards.put.Allowed {
				emit(s3ConstituentEdge(principal, target.arn, graph.KindCanPutObjectACL,
					aclWildcards.put.AllowSources, aclWildcards.put.Conditions))
				continue
			}
			pair := s3ObjectPair(ctx.evaluator, principal, target.arn,
				aclWildcards.get, aclWildcards.put, candidateMask)
			emitS3Pair(pair, emit)
		}
		for _, bucketIdx := range candidateBuckets {
			selected[bucketIdx] = 0
		}
		onPrincipal()
	}
}

type s3ACLWildcards struct {
	get eval.S3AccessCheckResult
	put eval.S3AccessCheckResult
}

// candidateBuckets returns exactly the buckets that could produce at least one
// targeted edge for principal. Identity grants can reach every same-account
// bucket, while cross-account access needs a bucket-policy principal grant;
// resource grants may stand alone in-account, and a supported public ACL may
// stand alone everywhere. Conditions and resource patterns stay conservative
// until the normal pair evaluation.
func (ctx *s3StreamContext) candidateBuckets(principal string, identityMask uint64, selected []uint64) []int {
	var out []int
	add := func(i int, mask uint64) {
		if mask == 0 {
			return
		}
		if selected[i] == 0 {
			out = append(out, i)
		}
		selected[i] |= mask
	}
	principalAccount := edgeAccountOf(principal)
	if identityMask != 0 {
		for _, i := range ctx.bucketsByOwner[principalAccount] {
			add(i, identityMask)
		}
	}
	for _, i := range ctx.policyByOwner[principalAccount] {
		b := &ctx.buckets[i]
		policyMask := ctx.evaluator.BucketPolicyMayAllowMask(b.arn, principal, s3TargetActions)
		add(i, policyMask)
	}
	if identityMask != 0 {
		addCrossPolicy := func(i int) {
			b := &ctx.buckets[i]
			if b.ownerAccount == principalAccount || ctx.evaluator.CrossAccountAccessAlwaysBlocked(b.arn) {
				return
			}
			add(i, identityMask&ctx.evaluator.BucketPolicyMayAllowMask(b.arn, principal, s3TargetActions))
		}
		for _, i := range ctx.policyByPrincipal[principal] {
			addCrossPolicy(i)
		}
		for _, i := range ctx.policyByAccount[principalAccount] {
			addCrossPolicy(i)
		}
		for _, i := range ctx.policyForAll {
			addCrossPolicy(i)
		}
		for _, i := range ctx.policyDynamic {
			addCrossPolicy(i)
		}
	}
	for _, i := range ctx.publicACLBuckets {
		b := &ctx.buckets[i]
		if b.ownerAccount != principalAccount && ctx.evaluator.CrossAccountAccessAlwaysBlocked(b.arn) {
			continue
		}
		add(i, b.publicACLMask)
	}
	return out
}

func s3ACLWildcardResults(ctx *s3StreamContext, principal string, bucket *s3StreamBucket, mask uint64) s3ACLWildcards {
	var out s3ACLWildcards
	if mask&s3BitGetObjectACL != 0 {
		out.get = ctx.evaluator.EvaluateS3Access(principal, "s3:GetObjectAcl", bucket.arn+"/*")
	}
	if mask&s3BitPutObjectACL != 0 {
		out.put = ctx.evaluator.EvaluateS3Access(principal, "s3:PutObjectAcl", bucket.arn+"/*")
	}
	return out
}

type s3TargetCursor struct {
	targets []s3StreamTarget
	pos     int
}

type s3TargetHeap []*s3TargetCursor

func newS3TargetHeap(ctx *s3StreamContext, buckets []int) *s3TargetHeap {
	h := make(s3TargetHeap, 0, len(buckets))
	for _, i := range buckets {
		if len(ctx.buckets[i].targets) > 0 {
			h = append(h, &s3TargetCursor{targets: ctx.buckets[i].targets})
		}
	}
	heap.Init(&h)
	return &h
}

func (h s3TargetHeap) Len() int      { return len(h) }
func (h s3TargetHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h s3TargetHeap) Less(i, j int) bool {
	return s3TargetLess(&h[i].targets[h[i].pos], &h[j].targets[h[j].pos])
}
func (h *s3TargetHeap) Push(x any) { *h = append(*h, x.(*s3TargetCursor)) }
func (h *s3TargetHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

func s3TargetLess(a, b *s3StreamTarget) bool {
	if a.arn != b.arn {
		return a.arn < b.arn
	}
	return !a.isObject && b.isObject
}

// s3BucketPair evaluates every constituent whose endpoint is the bucket. When no
// objects were collected anywhere, the object-family fallback also targets this
// pair; otherwise only PutObject's create-in-bucket edge participates here.
func s3BucketPair(ctx *s3StreamContext, principal string, bucket *s3StreamBucket, mask uint64) map[graph.EdgeKind]*graph.Edge {
	var pair map[graph.EdgeKind]*graph.Edge
	for _, spec := range s3SimpleBucketActions {
		if mask&spec.bit == 0 {
			continue
		}
		res := ctx.evaluator.EvaluateS3Access(principal, spec.action, bucket.arn)
		pair = s3PutAccessResult(pair, principal, bucket.arn, spec.kind, res)
	}

	objectResource := bucket.arn + "/*"
	if mask&s3BitPutObject != 0 {
		res := ctx.evaluator.EvaluateS3Access(principal, "s3:PutObject", objectResource)
		pair = s3PutAccessResult(pair, principal, bucket.arn, graph.KindCanPutObject, res)
	}
	if ctx.hasObjects {
		return pair
	}
	for _, spec := range []struct {
		action string
		kind   graph.EdgeKind
		bit    uint64
	}{
		{"s3:GetObject", graph.KindCanGetObject, s3BitGetObject},
		{"s3:DeleteObject", graph.KindCanDeleteObject, s3BitDeleteObject},
		{"s3:GetObjectAcl", graph.KindCanGetObjectACL, s3BitGetObjectACL},
		{"s3:PutObjectAcl", graph.KindCanPutObjectACL, s3BitPutObjectACL},
	} {
		if mask&spec.bit == 0 {
			continue
		}
		res := ctx.evaluator.EvaluateS3Access(principal, spec.action, objectResource)
		pair = s3PutAccessResult(pair, principal, bucket.arn, spec.kind, res)
	}
	return pair
}

// s3ObjectPair evaluates the five object constituents. Get/PutObjectAcl preserve
// the Python wildcard shortcut: an allowed bucket/* result is reused for every
// object; otherwise the concrete object is evaluated.
func s3ObjectPair(se *eval.S3Evaluator, principal, objectARN string, getACLWildcard, putACLWildcard eval.S3AccessCheckResult, mask uint64) map[graph.EdgeKind]*graph.Edge {
	var pair map[graph.EdgeKind]*graph.Edge
	for _, spec := range []struct {
		action string
		kind   graph.EdgeKind
		bit    uint64
	}{
		{"s3:GetObject", graph.KindCanGetObject, s3BitGetObject},
		{"s3:DeleteObject", graph.KindCanDeleteObject, s3BitDeleteObject},
		{"s3:PutObject", graph.KindCanPutObject, s3BitPutObject},
	} {
		if mask&spec.bit == 0 {
			continue
		}
		res := se.EvaluateS3Access(principal, spec.action, objectARN)
		pair = s3PutAccessResult(pair, principal, objectARN, spec.kind, res)
	}
	if mask&s3BitGetObjectACL != 0 {
		getACL := getACLWildcard
		if !getACL.Allowed {
			getACL = se.EvaluateS3Access(principal, "s3:GetObjectAcl", objectARN)
		}
		pair = s3PutAccessResult(pair, principal, objectARN, graph.KindCanGetObjectACL, getACL)
	}
	if mask&s3BitPutObjectACL != 0 {
		putACL := putACLWildcard
		if !putACL.Allowed {
			putACL = se.EvaluateS3Access(principal, "s3:PutObjectAcl", objectARN)
		}
		pair = s3PutAccessResult(pair, principal, objectARN, graph.KindCanPutObjectACL, putACL)
	}
	return pair
}

func s3PutAccessResult(pair map[graph.EdgeKind]*graph.Edge, start, end string, kind graph.EdgeKind, res eval.S3AccessCheckResult) map[graph.EdgeKind]*graph.Edge {
	if !res.Allowed {
		return pair
	}
	return s3PutPairEdge(pair, s3ConstituentEdge(start, end, kind, res.AllowSources, res.Conditions))
}

func s3PutPairEdge(pair map[graph.EdgeKind]*graph.Edge, e *graph.Edge) map[graph.EdgeKind]*graph.Edge {
	if pair == nil {
		pair = make(map[graph.EdgeKind]*graph.Edge)
	}
	pair[e.Kind] = e
	return pair
}

func emitS3Pair(pair map[graph.EdgeKind]*graph.Edge, emit func(*graph.Edge)) {
	if len(pair) == 1 {
		for _, e := range pair {
			emit(e)
		}
		return
	}
	for _, e := range s3ApplyMetaPair(pair) {
		emit(e)
	}
}

// s3AccountLevelEdge ports CanListAllMyBuckets / CanPutAccountPublicAccessBlock:
// evaluate the action against arn:aws:s3:::* and, if allowed, point the principal
// at its account's AWS_Account node.
func s3AccountLevelEdge(pe *eval.PolicyEvaluator, principal, accountRoot, action string, kind graph.EdgeKind) *graph.Edge {
	res := pe.CanPerformAction(principal, action, s3WildcardResource, nil)
	if !res.Allowed {
		return nil
	}
	return s3ConstituentEdge(principal, accountRoot, kind, res.AllowSources, res.Conditions)
}

// s3ConstituentEdge builds a per-permission S3 edge with the constituent property
// set — allow_sources then conditions, in that insertion order, and NO
// is_traversable (the Python S3 processors build Properties(allow_sources=...,
// conditions=...) directly, unlike the make_edge_properties helper the IAM edges
// use). is_traversable is added only on the meta edges (see s3_meta.go).
func s3ConstituentEdge(start, end string, kind graph.EdgeKind, allowSources []string, conditions []map[string]any) *graph.Edge {
	e := graph.NewEdge(start, end, kind)
	e.Set("allow_sources", strings.Join(allowSources, ", "))
	e.Set("conditions", conditionsJSON(conditions))
	return e
}

// iamIdentity adapts the identity-kernel PolicyEvaluator to the
// eval.IdentityEvaluator seam the S3 and Lambda resource evaluators compose with.
// pe.CanPerformAction carries an extra request-context argument and returns a
// pointer, so it cannot satisfy the interface directly; this is the IdentityFunc
// wrapper resource.go prescribes (passing a nil context yields the blank-context
// path, exactly as every other edge call site does). Shared with lambda.go.
func iamIdentity(pe *eval.PolicyEvaluator) eval.IdentityFunc {
	return func(principalArn, action, resourceArn string) eval.PermissionCheckResult {
		if res := pe.CanPerformAction(principalArn, action, resourceArn, nil); res != nil {
			return *res
		}
		return eval.PermissionCheckResult{}
	}
}

// s3EvalBucketPolicy parses a bucket policy into the eval AST, or nil when the
// bucket has none / it fails to parse. Bucket policies are PLAIN JSON (the raw
// GetBucketPolicy document), so they go through eval.ParseResourcePolicy, NOT
// eval.ParsePolicyDocument (which url-unescapes and is only for GAAD identity
// documents / trust policies).
func s3EvalBucketPolicy(raw json.RawMessage) *eval.Policy {
	if len(raw) == 0 {
		return nil
	}
	pol, err := eval.ParseResourcePolicy(raw)
	if err != nil {
		return nil
	}
	return pol
}

// s3EvalPAB maps a collected Block Public Access config into the eval type, or nil
// when absent. Used for both the per-bucket and account-level settings.
func s3EvalPAB(p *model.PublicAccessBlockConfiguration) *eval.PublicAccessBlock {
	if p == nil {
		return nil
	}
	return &eval.PublicAccessBlock{
		BlockPublicAcls:       p.BlockPublicAcls,
		IgnorePublicAcls:      p.IgnorePublicAcls,
		BlockPublicPolicy:     p.BlockPublicPolicy,
		RestrictPublicBuckets: p.RestrictPublicBuckets,
	}
}

// s3EvalACL maps a collected bucket ACL into the eval type, or nil when absent. The
// evaluator only reads each grant's grantee kind/id/uri and permission.
func s3EvalACL(acl *model.BucketACL) *eval.S3ACL {
	if acl == nil {
		return nil
	}
	out := &eval.S3ACL{}
	for _, g := range acl.Grants {
		var grantee eval.S3ACLGrantee
		if g.Grantee != nil {
			grantee = eval.S3ACLGrantee{Type: g.Grantee.Type, ID: g.Grantee.ID, URI: g.Grantee.URI}
		}
		out.Grants = append(out.Grants, eval.S3ACLGrant{Grantee: grantee, Permission: g.Permission})
	}
	return out
}
