package build

import (
	"strings"

	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// StreamNodes emits the node graph in the same order and with the same merged
// properties as MergeNodes(concat of AccountNodes) — first-appearance order,
// last-wins properties, unioned kinds — but holds only one account's nodes plus
// the small set of cross-account-shared nodes in memory at once. The
// volume-scaling majority (account-local nodes, including S3 object nodes) stream
// straight through the emit callback and are never accumulated (§9 of
// docs/authorization-tensor.md).
//
// Two node families have ids that recur across accounts: AWS-managed policies (the
// "aws" pseudo-account) and AWS_Account roots (the management account's org data
// emits a node for every member, which that member's own collection emits again).
// Every other node id embeds a real account id and is unique. Both shared families
// are bounded by the number of accounts and managed policies, not by resource
// volume, so a two-pass approach is exact and bounded: pass 1 merges just the shared
// nodes (reusing MergeNodes for identical semantics); pass 2 streams every account's
// nodes in order, substituting each shared node's merged form at its first
// appearance and skipping later duplicates.
// An optional onAccountDone callback fires once per account after that account's
// nodes have all been emitted (pass 2), letting a caller drive a per-account
// progress bar whose denominator is len(s.Accounts()).
func StreamNodes(s *store.Store, emit func(*graph.Node), onAccountDone ...func()) {
	accounts := s.Accounts()

	// Pass 1: collect and merge only the cross-account-shared nodes.
	var sharedNodes []*graph.Node
	for _, acct := range accounts {
		for _, n := range AccountNodes(acct) {
			if isCrossAccountShared(n.ID) {
				sharedNodes = append(sharedNodes, n)
			}
		}
	}
	merged := make(map[string]*graph.Node, len(sharedNodes))
	for _, n := range MergeNodes(sharedNodes) {
		merged[n.ID] = n
	}

	// Pass 2: stream in first-appearance order; a shared id emits its merged form
	// once, at first appearance.
	emitted := make(map[string]bool, len(merged))
	for _, acct := range accounts {
		for _, n := range AccountNodes(acct) {
			if isCrossAccountShared(n.ID) {
				if emitted[n.ID] {
					continue
				}
				emitted[n.ID] = true
				n = merged[n.ID]
			}
			emit(n)
		}
		for _, done := range onAccountDone {
			done()
		}
	}
}

// isCrossAccountShared reports whether a node id can recur across accounts:
//
//   - AWS-managed policies (arn:aws:iam::aws:...) use the shared "aws"
//     pseudo-account, so every account that has one emits the same id;
//   - AWS_Account roots (arn:aws:iam::<account>:root) are emitted both by the
//     account's own AccountRootNode and, for every member of a collected org, by the
//     management account's OrganizationsNodes.
//
// Every other node id embeds a real, account-unique id. Treating account roots as
// unique is what previously let StreamNodes emit the same AWS_Account node twice
// with disagreeing properties, diverging from the MergeNodes path this is
// documented to reproduce.
func isCrossAccountShared(id string) bool {
	return strings.HasPrefix(id, "arn:aws:iam::aws:") ||
		(strings.HasPrefix(id, "arn:aws:iam::") && strings.HasSuffix(id, ":root"))
}
