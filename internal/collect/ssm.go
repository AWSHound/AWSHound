package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// SSMCollector fetches AWS SSM Parameter Store metadata and the SSM-managed instance
// inventory (region-scoped; see the package doc). Per region, Fetch paginates
// DescribeParameters (metadata only — never a parameter's value) and
// DescribeInstanceInformation, merging everything into one SSMData.
type SSMCollector struct{}

// Service returns the collector's service identifier.
func (SSMCollector) Service() string { return "ssm" }

// Fetch collects every SSM parameter's metadata and every SSM-managed instance
// across the account's enabled regions. It mirrors SSMCollector.fetch: one pass
// paginates DescribeParameters (stamping each parameter's region), a second
// paginates DescribeInstanceInformation for the managed-instance inventory.
func (SSMCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	type ssmRegion struct {
		parameters       []model.SSMParameter
		managedInstances []model.SSMManagedInstance
	}
	perRegion, err := fanRegions(ctx, s, "ssm", func(ctx context.Context, region string) ssmRegion {
		client := ssm.NewFromConfig(s.regionCfg(region))
		return ssmRegion{
			parameters:       ssmFetchParameters(ctx, client, region),
			managedInstances: ssmFetchManagedInstances(ctx, client, region),
		}
	})
	if err != nil {
		return nil, err
	}

	var parameters []model.SSMParameter
	var managedInstances []model.SSMManagedInstance
	for _, r := range perRegion {
		parameters = append(parameters, r.parameters...)
		managedInstances = append(managedInstances, r.managedInstances...)
	}

	return &model.SSMData{
		AccountId:        accountID,
		Parameters:       parameters,
		ManagedInstances: managedInstances,
	}, nil
}

// ssmFetchParameters paginates DescribeParameters in one region, normalizing each
// ParameterMetadata into a model.SSMParameter and stamping the region. Ports the
// Python fetch_parameters closure; parameter listing is best-effort — a page error
// (e.g. region disabled / denied) stops this region and returns what was collected.
func ssmFetchParameters(ctx context.Context, client *ssm.Client, region string) []model.SSMParameter {
	var out []model.SSMParameter
	pager := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, p := range page.Parameters {
			out = append(out, model.SSMParameter{
				Name:             aws.ToString(p.Name),
				ARN:              aws.ToString(p.ARN),
				Type:             string(p.Type),
				KeyId:            aws.ToString(p.KeyId),
				Tier:             string(p.Tier),
				Version:          p.Version,
				LastModifiedDate: formatTime(p.LastModifiedDate),
				Description:      aws.ToString(p.Description),
				DataType:         aws.ToString(p.DataType),
				Region:           region,
				Tags:             ssmParameterTags(ctx, client, aws.ToString(p.Name)),
			})
		}
	}
	return out
}

// ssmParameterTags fetches one parameter's tags via ListTagsForResource, since
// DescribeParameters does not return them — needed so aws:ResourceTag/* conditions
// on ssm:* parameter actions resolve. On success it returns a non-nil slice (empty
// for an untagged parameter) so the evaluator treats a missing tag as ABSENT rather
// than UNKNOWN; a denied/failed call returns nil so those conditions stay UNKNOWN.
// This is one call per parameter (best-effort), the cost of tag data DescribeParameters
// omits. ResourceId is the parameter name, as the Parameter tagging API expects.
func ssmParameterTags(ctx context.Context, client *ssm.Client, name string) []model.Tag {
	if name == "" {
		return nil
	}
	out, err := client.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
		ResourceId:   aws.String(name),
	})
	if err != nil {
		return nil
	}
	tags := make([]model.Tag, 0, len(out.TagList))
	for _, t := range out.TagList {
		tags = append(tags, model.Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
	}
	return tags
}

// ssmFetchManagedInstances paginates DescribeInstanceInformation in one region,
// keeping the fields AWSHound records. Ports the Python fetch_managed_instances
// closure; like the parameter pass, a page error simply ends this region.
func ssmFetchManagedInstances(ctx context.Context, client *ssm.Client, region string) []model.SSMManagedInstance {
	var out []model.SSMManagedInstance
	pager := ssm.NewDescribeInstanceInformationPaginator(client, &ssm.DescribeInstanceInformationInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, info := range page.InstanceInformationList {
			out = append(out, model.SSMManagedInstance{
				InstanceId:   aws.ToString(info.InstanceId),
				PlatformType: string(info.PlatformType),
				PingStatus:   string(info.PingStatus),
				Region:       region,
			})
		}
	}
	return out
}
