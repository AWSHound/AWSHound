package store

import "github.com/AWSHound/AWSHound/internal/model"

// ssmService is the resource-bag key for SSM data. It matches SSMCollector.Service().
const ssmService = "ssm"

// ssmManagedInstancePrefix namespaces managed-instance keys in the SSM resource bag.
// Managed instances have no ARN, so they are keyed by prefix+InstanceId; parameter
// keys are ARNs ("arn:aws:ssm:..."), so the two never collide. The typed accessors
// below also discriminate by concrete type, so the prefix is belt-and-suspenders.
const ssmManagedInstancePrefix = "ssm-managed-instance:"

// IngestSSM stores a collected SSM payload on the given account. Every parameter
// lands in the account's generic resource bag keyed by its ARN, and that ARN is
// interned into the shared ARN universe so the evaluator can resolve SSM
// resource-pattern permissions. Managed instances are stored under a namespaced
// key (they have no ARN and are not part of the ARN universe — they are consumed by
// SSM edge processors, not by the resource resolver).
//
// It is the in-memory port of AWSHound's add_ssm_data (core/models/_queries/ssm.py),
// minus the DuckDB delete-then-insert replacement semantics: a parameter arriving
// without an ARN gets the synthesized arn:aws:ssm:{region}:{account}:parameter{name}
// (region defaulting to us-east-1), and a parameter with neither ARN nor Name is
// dropped — exactly as the Python does before the node parser ever sees it.
func IngestSSM(st *Store, accountID string, data *model.SSMData) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)

	for i := range data.Parameters {
		p := &data.Parameters[i]
		arn := p.ARN
		if arn == "" {
			if p.Name == "" {
				continue
			}
			region := p.Region
			if region == "" {
				region = "us-east-1"
			}
			arn = "arn:aws:ssm:" + region + ":" + accountID + ":parameter" + p.Name
			p.ARN = arn
		}
		acct.PutResource(ssmService, arn, p)
		st.ARN().Intern(arn)
	}

	for i := range data.ManagedInstances {
		mi := &data.ManagedInstances[i]
		if mi.InstanceId == "" {
			continue
		}
		acct.PutResource(ssmService, ssmManagedInstancePrefix+mi.InstanceId, mi)
	}
}

// SSMParameterList returns the SSM parameters ingested on this account, ordered by
// ARN so the node builder produces diff-stable output.
func (a *Account) SSMParameterList() []*model.SSMParameter {
	return listResources[model.SSMParameter](a, ssmService)
}

// SSMManagedInstanceList returns the SSM-managed instances ingested on this account,
// ordered by instance id for stable output (the bag key is ssmManagedInstancePrefix+
// InstanceId, which sorts identically). SSM edge processors use this set to decide
// which EC2 instances are reachable via SSM.
func (a *Account) SSMManagedInstanceList() []*model.SSMManagedInstance {
	return listResources[model.SSMManagedInstance](a, ssmService)
}
