package store

import "github.com/AWSHound/AWSHound/internal/model"

// ResourceTagsByArn returns the account's non-IAM/non-S3 service resources keyed
// by the ARN each is authorized against (its graph-node id), mapped to its tags in
// the IAM model.Tag (Key/Value) shape. It covers the resource kinds whose
// aws:ResourceTag/* conditions the policy evaluator must resolve: KMS keys, EC2
// instances, Lambda functions, SSM parameters, EKS clusters/nodegroups, and
// CloudFormation stacks.
//
// A resource is included only when its tags were actually collected (the source
// tag field is non-nil) — so a genuinely-untagged resource is present with an
// empty slice (its aws:ResourceTag conditions resolve ABSENT), while a resource
// whose tags were never collected is omitted (its conditions stay UNKNOWN and
// attacker bias still applies). This is the ABSENT-vs-UNKNOWN distinction: the
// evaluator must not assert a tag is missing on data it does not have.
func (a *Account) ResourceTagsByArn() map[string][]model.Tag {
	out := map[string][]model.Tag{}
	add := func(arn string, tags []model.Tag) {
		if arn == "" {
			return
		}
		if _, ok := out[arn]; !ok {
			out[arn] = tags
		}
	}
	for _, k := range a.KMSKeyList() {
		// KMS Tags are always non-nil (empty for AWS-managed keys).
		add(k.Arn, kmsTags(k.Tags))
	}
	for _, inst := range a.EC2InstanceList() {
		if inst.Tags != nil {
			add(ec2InstanceARN(a.ID, inst), inst.Tags)
		}
	}
	for _, fn := range a.LambdaFunctionList() {
		// ListFunctions does not return tags; Tags is nil unless re-ingested.
		if fn.Tags != nil {
			add(fn.FunctionArn, mapTags(fn.Tags))
		}
	}
	for _, p := range a.SSMParameterList() {
		// Live collection leaves parameter Tags nil.
		if p.Tags != nil {
			add(p.ARN, p.Tags)
		}
	}
	for _, c := range a.EKSClusterList() {
		if c.Tags != nil {
			add(c.Arn, mapTags(c.Tags))
		}
	}
	for _, ng := range a.EKSNodeGroupList() {
		if ng.Tags != nil {
			add(ng.NodegroupArn, mapTags(ng.Tags))
		}
	}
	for _, s := range a.CloudFormationStackList() {
		if s.Tags != nil {
			add(s.StackId, s.Tags)
		}
	}
	return out
}

// kmsTags converts KMS's TagKey/TagValue tag shape to the IAM model.Tag shape.
func kmsTags(tags []model.KMSTag) []model.Tag {
	out := make([]model.Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, model.Tag{Key: t.TagKey, Value: t.TagValue})
	}
	return out
}

// mapTags converts a map-shaped tag set (Lambda, EKS) to the IAM model.Tag shape.
func mapTags(tags map[string]string) []model.Tag {
	out := make([]model.Tag, 0, len(tags))
	for k, v := range tags {
		out = append(out, model.Tag{Key: k, Value: v})
	}
	return out
}
