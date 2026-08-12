package collect

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// orgRoleSessionName is the RoleSessionName stamped on every cross-account
// AssumeRole for an --org-role sweep, so the assumed sessions are identifiable in
// CloudTrail. It mirrors the Python AWSHound's "awshound-org-collection".
const orgRoleSessionName = "awshound-org-collection"

// ListOrgAccounts returns the caller's (management) account id and the ids of
// every ACTIVE account in its AWS Organization other than itself, via
// organizations:ListAccounts. It is the discovery step behind the CLI's
// --org-role sweep (the port of AWSHound's _discover_org_accounts): the caller
// then collects the management account directly and assumes a role into each
// child. The call must run against a management or delegated-admin identity;
// against any other account organizations:ListAccounts is denied and the error is
// returned so the caller can abort rather than silently collect nothing.
func ListOrgAccounts(ctx context.Context, s *Session) (mgmtID string, childIDs []string, err error) {
	mgmtID, err = s.AccountID(ctx)
	if err != nil {
		return "", nil, err
	}
	client := organizations.NewFromConfig(s.regionCfg(""))
	paginator := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
	for paginator.HasMorePages() {
		page, perr := paginator.NextPage(ctx)
		if perr != nil {
			return "", nil, fmt.Errorf("collect: organizations ListAccounts: %w", perr)
		}
		for _, a := range page.Accounts {
			if a.Status != orgtypes.AccountStatusActive {
				continue
			}
			id := aws.ToString(a.Id)
			if id == "" || id == mgmtID {
				continue
			}
			childIDs = append(childIDs, id)
		}
	}
	return mgmtID, childIDs, nil
}

// NewAssumeRoleSession builds a Session whose credentials come from assuming
// arn:aws:iam::<accountID>:role/<roleName> using base's credentials. It is the
// port of AWSHound's _assume_role_credentials: base is the management identity and
// the returned Session collects one organization child account.
//
// base is used purely as a credential/config template — its resolved config
// (retry policy, shared HTTP client, region) is copied and only the credentials
// provider is swapped for a lazily-refreshing STS AssumeRole provider, so base is
// not mutated and may back many child sessions concurrently. region, when
// non-empty, pins the child session's region the same way NewSessionFromFiles
// does; otherwise base's region is kept.
func NewAssumeRoleSession(base *Session, accountID, roleName, region string) (*Session, error) {
	if roleName == "" {
		return nil, fmt.Errorf("collect: assume-role for account %s: empty role name", accountID)
	}
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	stsClient := sts.NewFromConfig(base.regionCfg(""))
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = orgRoleSessionName
	})
	cfg := base.Cfg
	cfg.Credentials = aws.NewCredentialsCache(provider)
	if region != "" {
		cfg.Region = region
	}
	return &Session{Cfg: cfg, Region: cfg.Region}, nil
}
