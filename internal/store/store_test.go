package store

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/model"
)

func TestIngestGAADRoundTrip(t *testing.T) {
	const acct = "111122223333"
	gaad := &model.AuthDetails{
		UserDetailList: []model.UserDetail{
			{Arn: "arn:aws:iam::111122223333:user/alice", UserName: "alice"},
		},
		RoleDetailList: []model.RoleDetail{
			{Arn: "arn:aws:iam::111122223333:role/admin", RoleName: "admin"},
		},
		Policies: []model.PolicyDetail{
			{Arn: "arn:aws:iam::111122223333:policy/AdminAccess", PolicyName: "AdminAccess"},
		},
	}

	s := New()
	s.AddAuthDetails(acct, gaad)

	a := s.Account(acct)
	if got := a.Users["arn:aws:iam::111122223333:user/alice"]; got == nil || got.UserName != "alice" {
		t.Fatalf("user not ingested: %+v", got)
	}
	if got := a.Roles["arn:aws:iam::111122223333:role/admin"]; got == nil {
		t.Fatal("role not ingested")
	}
	if len(a.PrincipalARNs()) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(a.PrincipalARNs()))
	}

	// ARN universe: 3 ARNs interned, round-trip.
	if s.ARN().Size() != 3 {
		t.Fatalf("expected 3 interned ARNs, got %d", s.ARN().Size())
	}
	id, ok := s.ARN().ID("arn:aws:iam::111122223333:role/admin")
	if !ok || s.ARN().Arn(id) != "arn:aws:iam::111122223333:role/admin" {
		t.Fatal("ARN id round-trip failed")
	}
}

func TestAccountsSortedByID(t *testing.T) {
	s := New()
	// Insert out of order; Accounts() must return them sorted by id so downstream
	// output is reproducible regardless of map iteration order.
	for _, id := range []string{"444455556666", "111122223333", "999900001111", "222233334444"} {
		s.Account(id)
	}
	got := s.Accounts()
	want := []string{"111122223333", "222233334444", "444455556666", "999900001111"}
	if len(got) != len(want) {
		t.Fatalf("got %d accounts, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("Accounts()[%d] = %s, want %s (not sorted)", i, got[i].ID, w)
		}
	}
}

func TestAddAuthDetailsRetainsOnlyDefaultManagedPolicyVersions(t *testing.T) {
	const (
		acct      = "111122223333"
		policyARN = "arn:aws:iam::111122223333:policy/p"
	)
	s := New()
	s.AddAuthDetails(acct, &model.AuthDetails{Policies: []model.PolicyDetail{{
		Arn: policyARN, DefaultVersionId: "v2",
		PolicyVersions: []model.PolicyVersion{
			{VersionId: "v1", Document: "old"},
			{VersionId: "v2", IsDefaultVersion: true, Document: "active"},
		},
	}}})

	p := s.Account(acct).ManagedPolicies[policyARN]
	if p == nil {
		t.Fatal("managed policy was not ingested")
	}
	if len(p.PolicyVersions) != 1 || p.PolicyVersions[0].Document != "active" {
		t.Fatalf("retained versions = %+v, want only the active default", p.PolicyVersions)
	}
}

func TestResolvePattern(t *testing.T) {
	s := New()
	s.AddAuthDetails("111122223333", &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: "arn:aws:iam::111122223333:user/alice", UserName: "alice"}},
		RoleDetailList: []model.RoleDetail{
			{Arn: "arn:aws:iam::111122223333:role/admin", RoleName: "admin"},
			{Arn: "arn:aws:iam::111122223333:role/readonly", RoleName: "readonly"},
		},
	})
	x := s.ARN()

	// role/* matches both roles, not the user.
	roles := x.ResolvePattern("arn:aws:iam::111122223333:role/*")
	if roles.GetCardinality() != 2 {
		t.Fatalf("role/* should match 2, got %d", roles.GetCardinality())
	}
	// "*" matches the whole universe.
	if x.ResolvePattern("*").GetCardinality() != 3 {
		t.Fatalf("* should match 3, got %d", x.ResolvePattern("*").GetCardinality())
	}
	// Exact ARN matches exactly one.
	if x.ResolvePattern("arn:aws:iam::111122223333:user/alice").GetCardinality() != 1 {
		t.Fatal("exact ARN should match 1")
	}
	// Non-existent pattern matches none.
	if x.ResolvePattern("arn:aws:iam::999:role/*").GetCardinality() != 0 {
		t.Fatal("non-matching pattern should match 0")
	}
}
