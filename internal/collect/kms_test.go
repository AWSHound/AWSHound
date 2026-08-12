package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

type fakeKMSEnrichmentClient struct {
	policyCalls   int
	grantCalls    int
	tagCalls      int
	rotationCalls int
	policyError   error
}

func (s *fakeKMSEnrichmentClient) GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	s.policyCalls++
	if s.policyError != nil {
		return nil, s.policyError
	}
	return &kms.GetKeyPolicyOutput{Policy: aws.String(`{"Version":"2012-10-17","Statement":[]}`)}, nil
}

func TestKMSEnrichKeyMarksDeniedPolicyUnknown(t *testing.T) {
	client := &fakeKMSEnrichmentClient{policyError: errors.New("access denied")}
	key := &model.KMSKey{KeyId: "denied", KeyManager: "AWS"}
	kmsEnrichKey(context.Background(), client, key)

	if key.KeyPolicyKnown || len(key.KeyPolicy) != 0 {
		t.Fatalf("denied policy should remain unknown: known=%t policy=%s", key.KeyPolicyKnown, key.KeyPolicy)
	}
}

func (s *fakeKMSEnrichmentClient) ListGrants(context.Context, *kms.ListGrantsInput, ...func(*kms.Options)) (*kms.ListGrantsOutput, error) {
	s.grantCalls++
	return &kms.ListGrantsOutput{Grants: []kmstypes.GrantListEntry{{GrantId: aws.String("grant-1"), Operations: []kmstypes.GrantOperation{kmstypes.GrantOperationDecrypt}}}}, nil
}

func (s *fakeKMSEnrichmentClient) ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	s.tagCalls++
	return &kms.ListResourceTagsOutput{}, nil
}

func (s *fakeKMSEnrichmentClient) GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	s.rotationCalls++
	return &kms.GetKeyRotationStatusOutput{}, nil
}

func TestKMSEnrichKeyReadsAWSManagedPolicyAndGrants(t *testing.T) {
	client := &fakeKMSEnrichmentClient{}
	key := &model.KMSKey{KeyId: "aws-managed", KeyManager: "AWS", Grants: []model.KMSGrant{}, Tags: []model.KMSTag{}}
	kmsEnrichKey(context.Background(), client, key)

	if client.policyCalls != 1 || client.grantCalls != 1 {
		t.Fatalf("readable enrichment calls: policy=%d grants=%d; want 1/1", client.policyCalls, client.grantCalls)
	}
	if client.tagCalls != 0 || client.rotationCalls != 0 {
		t.Fatalf("editable enrichment ran for AWS key: tags=%d rotation=%d", client.tagCalls, client.rotationCalls)
	}
	if !key.KeyPolicyKnown || len(key.KeyPolicy) == 0 || len(key.Grants) != 1 {
		t.Fatalf("AWS-managed readable data not preserved: known=%t policy=%s grants=%v", key.KeyPolicyKnown, key.KeyPolicy, key.Grants)
	}
}
