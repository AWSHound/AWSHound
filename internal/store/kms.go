package store

import "github.com/AWSHound/AWSHound/internal/model"

// kmsService is the resource-bag key for KMS data. It matches KMSCollector.Service().
const kmsService = "kms"

// IngestKMS stores a collected KMS payload on the given account and interns every
// key ARN into the shared ARN universe. It is the in-memory analogue of AWSHound's
// add_kms_data (core/models/_queries/kms.py): each key lands in the account's
// generic resource bag under kmsService, keyed by its ARN. Keys without an ARN are
// skipped (they cannot be keyed and the node parser drops them anyway).
func IngestKMS(st *Store, accountID string, data *model.KMSData) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)
	for i := range data.Keys {
		k := &data.Keys[i]
		if k.Arn == "" {
			continue
		}
		acct.PutResource(kmsService, k.Arn, k)
		st.ARN().Intern(k.Arn)
	}
}

// KMSKeyList returns the KMS keys ingested on this account, ordered by ARN so
// callers (the node builder) produce diff-stable output.
func (a *Account) KMSKeyList() []*model.KMSKey { return listResources[model.KMSKey](a, kmsService) }
