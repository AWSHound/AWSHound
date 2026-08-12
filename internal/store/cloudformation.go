package store

import "github.com/AWSHound/AWSHound/internal/model"

// cloudformationService is the resource-bag key for CloudFormation data. It matches
// CloudFormationCollector.Service(). Both stacks and StackSets share this bag —
// they are disambiguated by their concrete Go type and their ARN namespaces never
// collide (a stack ARN carries ":stack/", a StackSet ARN carries ":stackset/").
const cloudformationService = "cloudformation"

// IngestCloudFormation stores a collected CloudFormation payload on the given account
// and interns every stack and StackSet ARN into the shared ARN universe. It is the
// in-memory analogue of AWSHound's ingest_cloudformation (core/storage/store.py):
// each stack lands keyed by its StackId (the stack ARN) and each StackSet keyed by
// its StackSetARN, both under cloudformationService. Stacks without a StackId and
// StackSets without a StackSetARN are skipped (they cannot be keyed and the node
// parser drops them anyway), matching the Python ingest's `if not arn: continue`.
func IngestCloudFormation(st *Store, accountID string, data *model.CloudFormationData) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)
	for i := range data.Stacks {
		s := &data.Stacks[i]
		if s.StackId == "" {
			continue
		}
		acct.PutResource(cloudformationService, s.StackId, s)
		st.ARN().Intern(s.StackId)
	}
	for i := range data.StackSets {
		ss := &data.StackSets[i]
		if ss.StackSetARN == "" {
			continue
		}
		acct.PutResource(cloudformationService, ss.StackSetARN, ss)
		st.ARN().Intern(ss.StackSetARN)
	}
}

// CloudFormationStackList returns the CloudFormation stacks ingested on this account,
// ordered by their StackId (the stack ARN) so callers (the node builder) produce
// diff-stable output. StackSets sharing the resource bag are filtered out by the type
// assertion.
func (a *Account) CloudFormationStackList() []*model.CloudFormationStack {
	return listResources[model.CloudFormationStack](a, cloudformationService)
}

// CloudFormationStackSetList returns the CloudFormation StackSets ingested on this
// account, ordered by their StackSetARN so callers produce diff-stable output. Stacks
// sharing the resource bag are filtered out by the type assertion.
func (a *Account) CloudFormationStackSetList() []*model.CloudFormationStackSet {
	return listResources[model.CloudFormationStackSet](a, cloudformationService)
}

// CloudFormationStackResourcePhysicalIDs maps every stack ARN to the non-empty
// PhysicalResourceIds of the resources it manages. It ports AWSHound's
// get_cloudformation_stack_resources (core/models/_queries/cloudformation.py) — the
// map the pass-role-via-CloudFormation edges use to relate a stack to the concrete
// resources it provisions. Resources without a physical id are skipped; per-stack id
// order follows the collected Resources order.
func (a *Account) CloudFormationStackResourcePhysicalIDs() map[string][]string {
	src := a.Resources(cloudformationService)
	out := make(map[string][]string)
	for arn, v := range src {
		stack, ok := v.(*model.CloudFormationStack)
		if !ok {
			continue
		}
		for _, r := range stack.Resources {
			if r.PhysicalResourceId == "" {
				continue
			}
			out[arn] = append(out[arn], r.PhysicalResourceId)
		}
	}
	return out
}
