package build

import (
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/store"
)

// AccountRootNode emits the AWS_Account node that anchors an account's principals,
// at arn:aws:iam::<account>:root. Ported from AWSHound's AccountNodeParser: the
// GAAD payload carries no account metadata beyond the IAM alias, so the base
// properties are the id, a synthetic ARN, and the account's resolved name when one
// is known. Organizations decoration (org_id / org_path / management_account_id /
// is_management_account) is merged in from OrganizationsNodes when org data has
// been collected.
func AccountRootNode(a *store.Account) []*graph.Node {
	if a.ID == "" {
		return nil
	}
	arn := "arn:aws:iam::" + a.ID + ":root"
	node := graph.NewNode(arn, graph.KindAccount).
		Set("account_id", a.ID).
		Set("arn", arn)
	setAccountName(node, a.ResolvedName())
	return []*graph.Node{node}
}

// setAccountName sets an AWS_Account node's human-readable name, or leaves the node
// untouched when no real name is known.
//
// Both properties carry the same value because the two consumers disagree on
// precedence: BloodHound reads name first and falls back to displayname, while
// StormChaser reads displayname first and falls back to name — and two of its call
// sites read displayname with no fallback at all. Setting only one satisfies one
// reader and silently leaves the other showing a bare 12-digit id.
//
// The empty check is the merge-order guard, and it is the whole reason a name is
// never defaulted to the account id here. MergeNodes is later-wins and the
// cross-account merge concatenates every account's nodes, so the management
// account's OrganizationsNodes and a member's own AccountRootNode both write the
// same node id. A parser that wrote the id as a fallback would clobber a real
// org-supplied name whenever the member happened to merge last — silently, and only
// in the multi-account org runs this feature exists for. Omitting instead lets a
// real name win by being the only writer, regardless of order. The id fallback is
// applied once after merging, by ApplyAccountNameFallback.
func setAccountName(node *graph.Node, name string) {
	if name == "" {
		return
	}
	node.Set("name", name)
	node.Set("displayname", name)
}

// ApplyAccountNameFallback gives an AWS_Account node that ended the merge with no
// known name the account id as its name, preserving the display behavior from
// before names were collected. It must run only after every writer of that node id
// has merged — see setAccountName for why a parser must never do this itself — so
// both build paths apply it in the runtime layer at emit, once the node is in its
// final merged form.
//
// displayname is deliberately left unset: an id is not a display name, and every
// displayname reader already falls back to the account id on its own.
func ApplyAccountNameFallback(n *graph.Node) {
	if n.Props.Has("name") {
		return
	}
	for _, k := range n.Kinds {
		if k != graph.KindAccount {
			continue
		}
		if id, ok := n.Props.Get("account_id").(string); ok && id != "" {
			n.Set("name", id)
		}
		return
	}
}
