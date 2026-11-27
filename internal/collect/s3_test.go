package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

type fakeS3AccountPABClient struct {
	calls     int
	accountID string
	cfg       *s3controltypes.PublicAccessBlockConfiguration
	err       error
}

func (f *fakeS3AccountPABClient) GetPublicAccessBlock(_ context.Context, in *s3control.GetPublicAccessBlockInput, _ ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	f.calls++
	if in != nil {
		f.accountID = aws.ToString(in.AccountId)
	}
	if f.err != nil {
		return nil, f.err
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.cfg}, nil
}

func TestS3AccountPABPopulatesConfiguration(t *testing.T) {
	client := &fakeS3AccountPABClient{
		cfg: &s3controltypes.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(false),
			RestrictPublicBuckets: aws.Bool(true),
		},
	}

	got := s3AccountPAB(context.Background(), client, "123456789012")
	if client.calls != 1 || client.accountID != "123456789012" {
		t.Fatalf("calls=%d accountID=%q; want 1 / 123456789012", client.calls, client.accountID)
	}
	want := model.PublicAccessBlockConfiguration{
		BlockPublicAcls:       true,
		IgnorePublicAcls:      true,
		BlockPublicPolicy:     false,
		RestrictPublicBuckets: true,
	}
	if got == nil || *got != want {
		t.Fatalf("s3AccountPAB = %+v, want %+v", got, want)
	}
}

func TestS3AccountPABBestEffortOnDeniedOrUnset(t *testing.T) {
	denied := &fakeS3AccountPABClient{err: errors.New("AccessDenied")}
	if got := s3AccountPAB(context.Background(), denied, "123456789012"); got != nil {
		t.Fatalf("denied s3AccountPAB = %+v, want nil", got)
	}

	unset := &fakeS3AccountPABClient{cfg: nil}
	if got := s3AccountPAB(context.Background(), unset, "123456789012"); got != nil {
		t.Fatalf("nil-config s3AccountPAB = %+v, want nil", got)
	}

	emptyAcct := &fakeS3AccountPABClient{}
	if got := s3AccountPAB(context.Background(), emptyAcct, ""); got != nil || emptyAcct.calls != 0 {
		t.Fatalf("empty account should skip call: got=%+v calls=%d", got, emptyAcct.calls)
	}
}
