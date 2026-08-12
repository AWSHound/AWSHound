package edges

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// StreamEdges must emit exactly the sequence AllEdges produces (deduped by
// (start,end,kind), first occurrence in family order) but without materializing
// the whole edge slice — the edge-side analogue of StreamNodes (§9).
func TestStreamEdgesMatchesAllEdges(t *testing.T) {
	s := store.New()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	s.AddAuthDetails("111111111111", &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: "arn:aws:iam::111111111111:user/admin", UserName: "admin",
			UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}}},
		RoleDetailList: []model.RoleDetail{{Arn: "arn:aws:iam::111111111111:role/r", RoleName: "r",
			AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}`}},
	})
	store.IngestSSM(s, "111111111111", &model.SSMData{Parameters: []model.SSMParameter{{Name: "/p", Region: "us-east-1"}}})
	store.IngestS3(s, "111111111111", &model.S3Data{Buckets: []model.S3Bucket{{
		Name: "stream-test", Objects: []model.S3Object{{Key: "object"}},
	}}})

	pe, err := eval.NewPolicyEvaluator(s)
	if err != nil {
		t.Fatal(err)
	}

	ref := AllEdges(s, pe)
	var got []*graph.Edge
	StreamEdges(s, pe, EdgeProgress{}, func(e *graph.Edge) { got = append(got, e) })

	if len(got) != len(ref) {
		t.Fatalf("StreamEdges emitted %d edges, AllEdges %d", len(got), len(ref))
	}
	for i := range ref {
		rb, _ := ref[i].MarshalJSON()
		gb, _ := got[i].MarshalJSON()
		if string(rb) != string(gb) {
			t.Fatalf("edge %d differs:\n stream: %s\n all:    %s", i, gb, rb)
		}
	}
}
