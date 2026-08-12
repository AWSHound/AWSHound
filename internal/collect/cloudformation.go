package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// CloudFormationCollector fetches AWS CloudFormation stack and StackSet data
// (region-scoped; see the package doc). Per region, Fetch paginates DescribeStacks —
// enriching each stack with its ListStackResources summaries — then lists StackSets
// and describes each for its permission model and administration/execution roles,
// stamping every stack and StackSet with the region it was found in. The stacks call
// and the StackSet call are independent, so a denial of one keeps the other.
type CloudFormationCollector struct{}

// Service returns the collector's service identifier.
func (CloudFormationCollector) Service() string { return "cloudformation" }

// Fetch collects every CloudFormation stack and StackSet across the account's enabled
// regions. It mirrors CloudFormationCollector.fetch: resolve the account id, discover
// regions, then per region paginate DescribeStacks (enriching each stack with its
// resources) and list + describe StackSets, merging all into one CloudFormationData.
func (CloudFormationCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	type cfRegion struct {
		stacks    []model.CloudFormationStack
		stackSets []model.CloudFormationStackSet
	}
	perRegion, err := fanRegions(ctx, s, "cloudformation", func(ctx context.Context, region string) cfRegion {
		client := cloudformation.NewFromConfig(s.regionCfg(region))

		var out cfRegion
		// Stacks, each enriched with its resource summaries.
		pager := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
		for pager.HasMorePages() {
			page, pageErr := pager.NextPage(ctx)
			if pageErr != nil {
				// Cannot describe stacks here (region disabled / denied); skip the
				// rest of this region's stacks, matching the Python per-region skip.
				break
			}
			for _, st := range page.Stacks {
				stack := cfConvertStack(st, region)
				stack.Resources = cfListStackResources(ctx, client, stack.StackName)
				out.stacks = append(out.stacks, stack)
			}
		}

		// StackSets — listed per home region, described individually for the admin/
		// exec roles the UpdateStackSet edges need. Independent of the stacks call so
		// a StackSet-API denial doesn't lose this region's stacks.
		out.stackSets = cfListStackSets(ctx, client, region)
		return out
	})
	if err != nil {
		return nil, err
	}

	var stacks []model.CloudFormationStack
	var stackSets []model.CloudFormationStackSet
	for _, r := range perRegion {
		stacks = append(stacks, r.stacks...)
		stackSets = append(stackSets, r.stackSets...)
	}

	// CloudFormationData.Region records the session's default region, the analogue of
	// the Python collector's default_region (session.region_name or "us-east-1").
	dataRegion := s.Region
	if dataRegion == "" {
		dataRegion = defaultRegion
	}

	return &model.CloudFormationData{
		AccountId: accountID,
		Region:    dataRegion,
		Stacks:    stacks,
		StackSets: stackSets,
	}, nil
}

// cfConvertStack maps one SDK stack to the collected model shape, stamping the region
// the Python collector injects. Capabilities and Tags are copied verbatim (Tag mirrors
// boto3's {"Key","Value"} so json.Marshal reproduces the node's "tags" payload).
func cfConvertStack(st cftypes.Stack, region string) model.CloudFormationStack {
	out := model.CloudFormationStack{
		StackName:   aws.ToString(st.StackName),
		StackId:     aws.ToString(st.StackId),
		RoleARN:     aws.ToString(st.RoleARN),
		StackStatus: string(st.StackStatus),
		Region:      region,
	}
	for _, c := range st.Capabilities {
		out.Capabilities = append(out.Capabilities, string(c))
	}
	for _, t := range st.Tags {
		out.Tags = append(out.Tags, model.Tag{
			Key:   aws.ToString(t.Key),
			Value: aws.ToString(t.Value),
		})
	}
	return out
}

// cfListStackResources paginates ListStackResources for a stack and returns its
// resource summaries, narrowed to the four fields the Python collector keeps. It ports
// the Python's try/except-wrapped enrichment: a failure yields no (or partial)
// resources rather than aborting the stack.
func cfListStackResources(ctx context.Context, client *cloudformation.Client, stackName string) []model.CloudFormationStackResource {
	var out []model.CloudFormationStackResource
	pager := cloudformation.NewListStackResourcesPaginator(client, &cloudformation.ListStackResourcesInput{
		StackName: aws.String(stackName),
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, sum := range page.StackResourceSummaries {
			out = append(out, model.CloudFormationStackResource{
				LogicalResourceId:  aws.ToString(sum.LogicalResourceId),
				PhysicalResourceId: aws.ToString(sum.PhysicalResourceId),
				ResourceType:       aws.ToString(sum.ResourceType),
				ResourceStatus:     string(sum.ResourceStatus),
			})
		}
	}
	return out
}

// cfListStackSets lists the region's StackSets and describes each one, returning the
// permission model, status, and administration/execution roles the UpdateStackSet /
// PassRole edges consume. It ports the Python's independently-wrapped StackSet block:
// a listing failure returns whatever was collected, a summary without a name is
// skipped, and a StackSet whose DescribeStackSet fails is dropped.
func cfListStackSets(ctx context.Context, client *cloudformation.Client, region string) []model.CloudFormationStackSet {
	var out []model.CloudFormationStackSet
	pager := cloudformation.NewListStackSetsPaginator(client, &cloudformation.ListStackSetsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, summary := range page.Summaries {
			name := aws.ToString(summary.StackSetName)
			if name == "" {
				continue
			}
			detail, descErr := client.DescribeStackSet(ctx, &cloudformation.DescribeStackSetInput{
				StackSetName: aws.String(name),
			})
			if descErr != nil || detail.StackSet == nil {
				continue
			}
			ss := detail.StackSet
			out = append(out, model.CloudFormationStackSet{
				StackSetName:          aws.ToString(ss.StackSetName),
				StackSetId:            aws.ToString(ss.StackSetId),
				StackSetARN:           aws.ToString(ss.StackSetARN),
				PermissionModel:       string(ss.PermissionModel),
				Status:                string(ss.Status),
				AdministrationRoleARN: aws.ToString(ss.AdministrationRoleARN),
				ExecutionRoleName:     aws.ToString(ss.ExecutionRoleName),
				Region:                region,
			})
		}
	}
	return out
}
