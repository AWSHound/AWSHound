package build_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/build"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

const (
	mgmtAcct   = "111111111111"
	memberAcct = "222222222222"
)

// orgData returns an org rooted at mgmtAcct with memberAcct as its one other
// member, naming both accounts.
func orgData() *model.OrganizationsData {
	return &model.OrganizationsData{
		Organization: model.Organization{
			Id:              "o-abc",
			Arn:             "arn:aws:organizations::" + mgmtAcct + ":organization/o-abc",
			MasterAccountId: mgmtAcct,
			FeatureSet:      "ALL",
		},
		AccountOrgPaths: map[string]string{
			mgmtAcct:   "o-abc/r-root/",
			memberAcct: "o-abc/r-root/ou-dev/",
		},
		AccountNames: map[string]string{
			mgmtAcct:   "org-management",
			memberAcct: "prod-payments",
		},
	}
}

// gaadFor returns a minimal GAAD payload for an account, optionally carrying an
// IAM account alias.
func gaadFor(accountID, alias string) *model.AuthDetails {
	return &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: "arn:aws:iam::" + accountID + ":user/bob", UserName: "bob"},
		},
		AccountAlias: alias,
	}
}

// accountNode returns the merged AWS_Account node for an account id, as the build
// pipeline's in-process path produces it (MergeNodes + the emit-time fallback that
// runtime applies).
func accountNode(t *testing.T, s *store.Store, accountID string) *graph.Node {
	t.Helper()
	var all []*graph.Node
	for _, acct := range s.Accounts() {
		all = append(all, build.AccountNodes(acct)...)
	}
	want := "arn:aws:iam::" + accountID + ":root"
	for _, n := range build.MergeNodes(all) {
		if n.ID != want {
			continue
		}
		build.ApplyAccountNameFallback(n)
		return n
	}
	t.Fatalf("no AWS_Account node for %s", accountID)
	return nil
}

func prop(t *testing.T, n *graph.Node, key string) any {
	t.Helper()
	if !n.Props.Has(key) {
		t.Fatalf("node %s has no %q property", n.ID, key)
	}
	return n.Props.Get(key)
}

// A member account's org-supplied name must survive the cross-account merge no
// matter which account merges last. This is the regression the whole omit-don't-
// default guard exists for: the member's own AccountRootNode and the management
// account's OrganizationsNodes both write the member's node id, and a parser that
// defaulted name to the account id would silently clobber the good org name in
// exactly the multi-account org runs this feature targets.
func TestOrgAccountNameSurvivesMergeOrder(t *testing.T) {
	// The member is collected itself (no alias, so the id is its only local name
	// candidate) and is also described by the management account's org data.
	// s.Accounts() sorts by id, so the member merges last — the losing order.
	s := store.New()
	store.IngestOrganizations(s, mgmtAcct, orgData())
	s.AddAuthDetails(mgmtAcct, gaadFor(mgmtAcct, ""))
	s.AddAuthDetails(memberAcct, gaadFor(memberAcct, ""))

	n := accountNode(t, s, memberAcct)
	if got := prop(t, n, "name"); got != "prod-payments" {
		t.Errorf("name = %v, want the org-supplied name (the member's own node clobbered it)", got)
	}
	if got := prop(t, n, "displayname"); got != "prod-payments" {
		t.Errorf("displayname = %v, want prod-payments", got)
	}
}

// The org name is authoritative over the account's own IAM alias when a member has
// both — and the winner must not depend on how the two account ids sort. Accounts
// merge in id order, so the member's own node merges last in the first case and
// first in the second; the org name has to win either way.
func TestOrgNameWinsOverLocalAlias(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mgmt   string
		member string
	}{
		{"member sorts after management", "111111111111", "222222222222"},
		{"member sorts before management", "999999999999", "333333333333"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := orgData()
			data.Organization.MasterAccountId = tc.mgmt
			data.AccountOrgPaths = map[string]string{
				tc.mgmt:   "o-abc/r-root/",
				tc.member: "o-abc/r-root/ou-dev/",
			}
			data.AccountNames = map[string]string{
				tc.mgmt:   "org-management",
				tc.member: "prod-payments",
			}

			s := store.New()
			store.IngestOrganizations(s, tc.mgmt, data)
			s.AddAuthDetails(tc.member, gaadFor(tc.member, "payments-alias"))

			if got := prop(t, accountNode(t, s, tc.member), "name"); got != "prod-payments" {
				t.Errorf("name = %v, want the org name to win over the IAM alias", got)
			}
		})
	}
}

// A standalone account has no org data, so its IAM alias is its only name source.
func TestStandaloneAccountUsesIAMAlias(t *testing.T) {
	s := store.New()
	s.AddAuthDetails(memberAcct, gaadFor(memberAcct, "solo-sandbox"))

	n := accountNode(t, s, memberAcct)
	if got := prop(t, n, "name"); got != "solo-sandbox" {
		t.Errorf("name = %v, want solo-sandbox", got)
	}
	if got := prop(t, n, "displayname"); got != "solo-sandbox" {
		t.Errorf("displayname = %v, want solo-sandbox", got)
	}
}

// An account with no name from any source keeps the pre-existing display behavior:
// name falls back to the account id at emit. displayname stays unset — an id is not
// a display name.
func TestUnnamedAccountFallsBackToID(t *testing.T) {
	s := store.New()
	s.AddAuthDetails(memberAcct, gaadFor(memberAcct, ""))

	n := accountNode(t, s, memberAcct)
	if got := prop(t, n, "name"); got != memberAcct {
		t.Errorf("name = %v, want the account id fallback %s", got, memberAcct)
	}
	if n.Props.Has("displayname") {
		t.Errorf("displayname = %v, want it unset for an unnamed account", n.Props.Get("displayname"))
	}
}

// is_management_account must be an explicit boolean on both the management account
// and its members — StormChaser's discover_orgs matches on `= true` and its attack
// path targeting queries the same predicate.
func TestIsManagementAccountFlag(t *testing.T) {
	s := store.New()
	store.IngestOrganizations(s, mgmtAcct, orgData())

	if got := prop(t, accountNode(t, s, mgmtAcct), "is_management_account"); got != true {
		t.Errorf("management account: is_management_account = %v, want true", got)
	}
	if got := prop(t, accountNode(t, s, memberAcct), "is_management_account"); got != false {
		t.Errorf("member account: is_management_account = %v, want an explicit false", got)
	}
}

// Absent is distinct from false: without org data nothing knows whether the account
// is the management account, and the flag must not claim otherwise.
func TestIsManagementAccountAbsentWithoutOrgData(t *testing.T) {
	s := store.New()
	s.AddAuthDetails(memberAcct, gaadFor(memberAcct, ""))

	if n := accountNode(t, s, memberAcct); n.Props.Has("is_management_account") {
		t.Errorf("is_management_account = %v, want absent when no org data was collected",
			n.Props.Get("is_management_account"))
	}
}

// A partial DescribeOrganization (no MasterAccountId) yields no flag rather than a
// wrong one — the same guard that already gates management_account_id.
func TestIsManagementAccountAbsentOnPartialOrg(t *testing.T) {
	data := orgData()
	data.Organization.MasterAccountId = ""
	s := store.New()
	store.IngestOrganizations(s, mgmtAcct, data)

	if n := accountNode(t, s, memberAcct); n.Props.Has("is_management_account") {
		t.Errorf("is_management_account = %v, want absent when the org has no MasterAccountId",
			n.Props.Get("is_management_account"))
	}
}

// An org member's AWS_Account node is written twice — by the management account's
// org data and by the member's own collection — so StreamNodes must merge it rather
// than emit it twice. It previously treated account roots as account-unique and
// emitted both copies, with disagreeing org properties and environmentid, diverging
// from the MergeNodes path it is documented to reproduce byte for byte.
func TestStreamNodesMergesOrgAccountRoots(t *testing.T) {
	s := store.New()
	store.IngestOrganizations(s, mgmtAcct, orgData())
	s.AddAuthDetails(mgmtAcct, gaadFor(mgmtAcct, ""))
	s.AddAuthDetails(memberAcct, gaadFor(memberAcct, ""))

	var streamed []*graph.Node
	build.StreamNodes(s, func(n *graph.Node) { streamed = append(streamed, n) })

	memberRoot := "arn:aws:iam::" + memberAcct + ":root"
	var seen int
	for _, n := range streamed {
		if n.ID == memberRoot {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("StreamNodes emitted %d nodes for %s, want exactly 1", seen, memberRoot)
	}

	// And the surviving node must agree with the reference merge, org decoration
	// and all.
	ref := referenceNodes(s)
	if len(streamed) != len(ref) {
		t.Fatalf("streamed %d nodes, reference merged %d", len(streamed), len(ref))
	}
	for i := range ref {
		if got, want := nodeJSON(t, streamed[i]), nodeJSON(t, ref[i]); got != want {
			t.Errorf("node %d differs:\n stream: %s\n merge:  %s", i, got, want)
		}
	}
}

// An org member the org reported no name for carries no name from the org path, so
// the id fallback applies — the map lookup must not write an empty name.
func TestUnnamedOrgMemberOmitsName(t *testing.T) {
	data := orgData()
	delete(data.AccountNames, memberAcct)
	s := store.New()
	store.IngestOrganizations(s, mgmtAcct, data)

	n := accountNode(t, s, memberAcct)
	if got := prop(t, n, "name"); got != memberAcct {
		t.Errorf("name = %v, want the id fallback for an org member with no name", got)
	}
	if n.Props.Has("displayname") {
		t.Errorf("displayname = %v, want it unset", n.Props.Get("displayname"))
	}
}
