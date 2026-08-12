package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// EC2Collector fetches AWS EC2 instance data (region-scoped; see the package doc).
// Per region, Fetch paginates DescribeInstances, flattening every reservation's
// instances and stamping each with its region — the analogue of the Python collector
// injecting instance["Region"] = region.
type EC2Collector struct{}

// Service returns the collector's service identifier.
func (EC2Collector) Service() string { return "ec2" }

// Fetch collects every EC2 instance across the account's enabled regions. It mirrors
// EC2Collector.fetch: resolve the account id, discover regions, then paginate
// DescribeInstances per region, merging all instances into one EC2Data.
func (EC2Collector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	perRegion, err := fanRegions(ctx, s, "ec2", func(ctx context.Context, region string) []model.EC2Instance {
		client := ec2.NewFromConfig(s.regionCfg(region))
		var instances []model.EC2Instance
		pager := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
		for pager.HasMorePages() {
			page, pageErr := pager.NextPage(ctx)
			if pageErr != nil {
				// Cannot describe instances here (region disabled / denied); skip the
				// rest of this region, matching the Python per-region on_error skip.
				break
			}
			for _, reservation := range page.Reservations {
				for _, inst := range reservation.Instances {
					instances = append(instances, ec2ConvertInstance(inst, region))
				}
			}
		}
		return instances
	})
	if err != nil {
		return nil, err
	}

	var instances []model.EC2Instance
	for _, r := range perRegion {
		instances = append(instances, r...)
	}
	return &model.EC2Data{AccountId: accountID, Instances: instances}, nil
}

// ec2ConvertInstance maps one SDK instance to the collected model shape, stamping the
// region the Python collector injects. Nested pointers (State, IamInstanceProfile,
// Ebs) are nil-checked so a sparse instance converts cleanly; the IAM profile is left
// nil when absent, matching the Python's `instance.get("IamInstanceProfile")`.
func ec2ConvertInstance(inst ec2types.Instance, region string) model.EC2Instance {
	out := model.EC2Instance{
		InstanceId:       aws.ToString(inst.InstanceId),
		Region:           region,
		InstanceType:     string(inst.InstanceType),
		ImageId:          aws.ToString(inst.ImageId),
		VpcId:            aws.ToString(inst.VpcId),
		SubnetId:         aws.ToString(inst.SubnetId),
		PrivateIpAddress: aws.ToString(inst.PrivateIpAddress),
		PublicIpAddress:  aws.ToString(inst.PublicIpAddress),
		LaunchTime:       formatTime(inst.LaunchTime),
		RootDeviceName:   aws.ToString(inst.RootDeviceName),
	}
	if inst.State != nil {
		out.State = model.EC2State{Name: string(inst.State.Name)}
	}
	if inst.IamInstanceProfile != nil {
		out.IamInstanceProfile = &model.EC2IamInstanceProfile{
			Arn: aws.ToString(inst.IamInstanceProfile.Arn),
			Id:  aws.ToString(inst.IamInstanceProfile.Id),
		}
	}
	for _, sg := range inst.SecurityGroups {
		out.SecurityGroups = append(out.SecurityGroups, model.EC2SecurityGroup{
			GroupName: aws.ToString(sg.GroupName),
			GroupId:   aws.ToString(sg.GroupId),
		})
	}
	for _, t := range inst.Tags {
		out.Tags = append(out.Tags, model.Tag{
			Key:   aws.ToString(t.Key),
			Value: aws.ToString(t.Value),
		})
	}
	for _, bdm := range inst.BlockDeviceMappings {
		mapping := model.EC2BlockDeviceMapping{DeviceName: aws.ToString(bdm.DeviceName)}
		if bdm.Ebs != nil {
			mapping.Ebs = &model.EC2EbsDevice{VolumeId: aws.ToString(bdm.Ebs.VolumeId)}
		}
		out.BlockDeviceMappings = append(out.BlockDeviceMappings, mapping)
	}
	return out
}
