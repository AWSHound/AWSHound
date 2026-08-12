package edges

import (
	"encoding/json"
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

func TestS3ApplyMetaPairFiresWholeWaveBeforeSuppression(t *testing.T) {
	const (
		start = "arn:aws:iam::111122223333:user/u"
		end   = "arn:aws:s3:::bucket"
	)
	pair := map[graph.EdgeKind]*graph.Edge{}
	add := func(kinds ...graph.EdgeKind) {
		for _, kind := range kinds {
			e := graph.NewEdge(start, end, kind)
			e.Set("allow_sources", string(kind))
			e.Set("conditions", "")
			pair[kind] = e
		}
	}
	add(s3ObjectAll.constituents...)
	add(s3BucketAll.constituents...)

	got := s3ApplyMetaPair(pair)
	if len(got) != 2 {
		t.Fatalf("got %d surviving edges, want the two ALL metas: %+v", len(got), got)
	}
	if got[0].Kind != graph.KindS3BucketAll || got[1].Kind != graph.KindS3ObjectAll {
		t.Fatalf("meta kinds/order = [%s, %s], want bucket-all then object-all", got[0].Kind, got[1].Kind)
	}
}

func TestStreamS3EdgesIsSortedUniqueAndConsolidated(t *testing.T) {
	const acct = "111122223333"
	principal := "arn:aws:iam::" + acct + ":user/admin"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(acct, &model.AuthDetails{UserDetailList: []model.UserDetail{{
		Arn: principal, UserName: "admin",
		UserPolicyList: []model.InlinePolicy{{PolicyName: "s3-admin", PolicyDocument: doc}},
	}}})
	store.IngestS3(s, acct, &model.S3Data{Buckets: []model.S3Bucket{
		{Name: "a", Objects: []model.S3Object{{Key: "z"}, {Key: "z"}}}, // duplicate key must collapse
		{Name: "a-", Objects: []model.S3Object{{Key: "z"}}},
	}})
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	var got [][3]string
	StreamS3Edges(s, pe, func(e *graph.Edge) {
		got = append(got, [3]string{e.Start, e.End, string(e.Kind)})
	})
	want := [][3]string{
		{principal, "arn:aws:iam::" + acct + ":root", string(graph.KindCanListAllMyBuckets)},
		{principal, "arn:aws:iam::" + acct + ":root", string(graph.KindCanPutAccountPublicAccessBlock)},
		{principal, "arn:aws:s3:::a", string(graph.KindS3BucketAll)},
		// Global endpoint ordering, not bucket-grouped ordering: '-' sorts before '/'.
		{principal, "arn:aws:s3:::a-", string(graph.KindS3BucketAll)},
		{principal, "arn:aws:s3:::a-/z", string(graph.KindS3ObjectAll)},
		{principal, "arn:aws:s3:::a/z", string(graph.KindS3ObjectAll)},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d edges, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("edge %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestStreamS3EdgesCandidatePruningKeepsEveryGrantLayer(t *testing.T) {
	const (
		owner = "111122223333"
		other = "444455556666"
	)
	local := "arn:aws:iam::" + owner + ":user/local"
	cross := "arn:aws:iam::" + other + ":user/cross"
	aclOnly := "arn:aws:iam::" + other + ":user/acl-only"
	rootMatch := "arn:aws:iam::" + other + ":user/root-match"
	bareMatch := "arn:aws:iam::" + other + ":user/bare-match"
	globMatch := "arn:aws:iam::" + other + ":user/glob-match"
	notMatch := "arn:aws:iam::" + other + ":user/not-match"
	wildMatch := "arn:aws:iam::" + other + ":user/wild-match"
	crossDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}]}`
	s := store.New()
	s.AddAuthDetails(owner, &model.AuthDetails{UserDetailList: []model.UserDetail{{Arn: local, UserName: "local"}}})
	s.AddAuthDetails(other, &model.AuthDetails{UserDetailList: []model.UserDetail{
		{Arn: cross, UserName: "cross", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: crossDoc}}},
		{Arn: aclOnly, UserName: "acl-only"},
		{Arn: rootMatch, UserName: "root-match", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: crossDoc}}},
		{Arn: bareMatch, UserName: "bare-match", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: crossDoc}}},
		{Arn: globMatch, UserName: "glob-match", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: crossDoc}}},
		{Arn: notMatch, UserName: "not-match", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: crossDoc}}},
		{Arn: wildMatch, UserName: "wild-match", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: crossDoc}}},
	}})
	policy := json.RawMessage(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/local"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:user/cross"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
		{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:user/glob-*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
		{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::444455556666:user/excluded"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"},
		{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}
	]}`)
	store.IngestS3(s, owner, &model.S3Data{Buckets: []model.S3Bucket{{
		Name: "shared", BucketPolicy: policy, Objects: []model.S3Object{{Key: "policy-object"}},
	}, {
		Name: "public-acl",
		Acl: &model.BucketACL{Grants: []model.ACLGrant{{Grantee: &model.ACLGrantee{
			Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers",
		}, Permission: "READ"}}},
		Objects: []model.S3Object{{Key: "acl-object"}},
	}}})
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	found := map[[2]string]bool{}
	StreamS3Edges(s, pe, func(e *graph.Edge) {
		if e.Kind == graph.KindCanGetObject {
			found[[2]string{e.Start, e.End}] = true
		}
	})
	for _, pair := range [][2]string{
		{local, "arn:aws:s3:::shared/policy-object"},
		{cross, "arn:aws:s3:::shared/policy-object"},
		{rootMatch, "arn:aws:s3:::shared/policy-object"},
		{bareMatch, "arn:aws:s3:::shared/policy-object"},
		{globMatch, "arn:aws:s3:::shared/policy-object"},
		{notMatch, "arn:aws:s3:::shared/policy-object"},
		{wildMatch, "arn:aws:s3:::shared/policy-object"},
		{aclOnly, "arn:aws:s3:::public-acl/acl-object"},
	} {
		if !found[pair] {
			t.Errorf("candidate pruning dropped expected S3 grant %v", pair)
		}
	}
}

func TestStreamS3EdgesResolvesBucketPolicyConditionsFromStore(t *testing.T) {
	const (
		owner   = "111122223333"
		allowed = "444455556666"
		denied  = "777788889999"
	)
	allowedARN := "arn:aws:iam::" + allowed + ":user/allowed"
	deniedARN := "arn:aws:iam::" + denied + ":user/denied"
	identityDoc := `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::conditioned/*"}}`
	s := store.New()
	s.AddAuthDetails(allowed, &model.AuthDetails{UserDetailList: []model.UserDetail{{
		Arn: allowedARN, UserName: "allowed", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: identityDoc}},
	}}})
	s.AddAuthDetails(denied, &model.AuthDetails{UserDetailList: []model.UserDetail{{
		Arn: deniedARN, UserName: "denied", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: identityDoc}},
	}}})
	policy := json.RawMessage(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::conditioned/*","Condition":{"StringEquals":{"aws:PrincipalAccount":"444455556666"}}}}`)
	store.IngestS3(s, owner, &model.S3Data{Buckets: []model.S3Bucket{{
		Name: "conditioned", BucketPolicy: policy, Objects: []model.S3Object{{Key: "object"}},
	}}})
	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	StreamS3Edges(s, pe, func(e *graph.Edge) {
		if e.Kind == graph.KindCanGetObject && e.End == "arn:aws:s3:::conditioned/object" {
			found[e.Start] = true
		}
	})
	if !found[allowedARN] {
		t.Fatal("matching principal-account condition did not grant bucket-policy edge")
	}
	if found[deniedARN] {
		t.Fatal("known-false principal-account condition was retained as an edge")
	}
}
