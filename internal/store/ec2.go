package store

import (
	"fmt"

	"github.com/AWSHound/AWSHound/internal/model"
)

// ec2Service is the resource-bag key for EC2 data. It matches EC2Collector.Service().
const ec2Service = "ec2"

// IngestEC2 stores a collected EC2 payload on the given account and interns every
// synthesized instance ARN into the shared ARN universe. It is the in-memory analogue
// of AWSHound's ingest_ec2 (core/storage/store.py): each instance lands in the
// account's generic resource bag under ec2Service, keyed by its synthesized ARN
// arn:aws:ec2:<region>:<account>:instance/<id>. Instances without an id are skipped
// (they cannot be keyed and the node parser drops them anyway).
func IngestEC2(st *Store, accountID string, data *model.EC2Data) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)
	for i := range data.Instances {
		inst := &data.Instances[i]
		if inst.InstanceId == "" {
			continue
		}
		arn := ec2InstanceARN(accountID, inst)
		acct.PutResource(ec2Service, arn, inst)
		// Instance ARNs are deliberately NOT interned into the evaluation universe
		// (§4 eviction): they scale with data volume, not policy structure. Edge
		// families enumerate instances from the resource bag and CanPerformAction
		// regex-matches the (un-interned) instance ARN, so eviction bounds the
		// universe without changing graph output.
	}
}

// EC2InstanceList returns the EC2 instances ingested on this account, ordered by their
// synthesized ARN so callers (the node builder) produce diff-stable output.
func (a *Account) EC2InstanceList() []*model.EC2Instance {
	return listResources[model.EC2Instance](a, ec2Service)
}

// EC2InstanceVolumeARNs maps every instance ARN to the EBS volume ARNs attached to it,
// derived from each instance's BlockDeviceMappings. It ports AWSHound's
// get_ec2_instance_volume_arns (core/models/_queries/ec2.py): a volume ARN is
// arn:aws:ec2:<region>:<account>:volume/<id>, and mappings without an EBS volume id
// are skipped. Volume order follows BlockDeviceMappings order, matching the Python.
func (a *Account) EC2InstanceVolumeARNs() map[string][]string {
	src := a.Resources(ec2Service)
	out := make(map[string][]string, len(src))
	for arn, v := range src {
		inst, ok := v.(*model.EC2Instance)
		if !ok {
			continue
		}
		region := inst.Region
		if region == "" {
			region = "us-east-1"
		}
		for _, bdm := range inst.BlockDeviceMappings {
			if bdm.Ebs == nil || bdm.Ebs.VolumeId == "" {
				continue
			}
			volumeARN := fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", region, a.ID, bdm.Ebs.VolumeId)
			out[arn] = append(out[arn], volumeARN)
		}
	}
	return out
}

// ec2InstanceARN synthesizes an instance's ARN from its region and id, defaulting the
// region to us-east-1 when absent — matching AWSHound's ingest_ec2, which builds
// arn:aws:ec2:<region>:<account>:instance/<id> with `region or "us-east-1"`.
func ec2InstanceARN(accountID string, inst *model.EC2Instance) string {
	region := inst.Region
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, inst.InstanceId)
}
