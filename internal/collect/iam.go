package collect

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// IAMCollector fetches AWS IAM authorization data (a global collector; see the
// package doc). It runs iam:GetAccountAuthorizationDetails (GAAD) with full
// pagination, merging every page's Users/Groups/Roles/Policies into a single
// *model.AuthDetails, then attaches the account's SAML and OIDC identity providers
// (enumerated separately — they are not part of GAAD).
type IAMCollector struct{}

// Service returns the service identifier, matching BaseCollector._service_name.
func (IAMCollector) Service() string { return "iam" }

// Fetch collects the session account's IAM authorization details. The returned
// *model.AuthDetails is ingested by store.AddAuthDetails.
func (IAMCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	if err := s.limiter.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.limiter.release()
	defer s.tick()

	client := iam.NewFromConfig(s.regionCfg(""))

	data := &model.AuthDetails{
		UserDetailList:  []model.UserDetail{},
		GroupDetailList: []model.GroupDetail{},
		RoleDetailList:  []model.RoleDetail{},
		Policies:        []model.PolicyDetail{},
	}

	// GetAccountAuthorizationDetails with no Filter returns users, groups, roles,
	// and both customer- and AWS-managed policies. Paginate the full result set.
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(client, &iam.GetAccountAuthorizationDetailsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("collect: iam GetAccountAuthorizationDetails: %w", err)
		}
		for i := range page.UserDetailList {
			data.UserDetailList = append(data.UserDetailList, iamConvertUser(page.UserDetailList[i]))
		}
		for i := range page.GroupDetailList {
			data.GroupDetailList = append(data.GroupDetailList, iamConvertGroup(page.GroupDetailList[i]))
		}
		for i := range page.RoleDetailList {
			data.RoleDetailList = append(data.RoleDetailList, iamConvertRole(page.RoleDetailList[i]))
		}
		for i := range page.Policies {
			data.Policies = append(data.Policies, iamConvertManagedPolicy(page.Policies[i]))
		}
		// GAAD pagination is inherently sequential (each page needs the prior
		// page's marker) and is the bulk of IAM collection time on a large account.
		// Count and tick one unit per fetched page so this single-unit global
		// collector advances page-by-page rather than only ticking once at the very
		// end. NextPage errors return above before this pair runs. See
		// Session.addWork.
		s.addWork(1)
		s.tick()
	}

	// SAML/OIDC identity providers are NOT part of GAAD — enumerate them directly
	// so provider nodes come from observation, not from trust policies that merely
	// reference a provider ARN. Both are best-effort: a missing permission yields
	// what was obtained rather than failing the whole IAM collection (matching the
	// Python collector's ClientError handling).
	data.SAMLProviders = iamFetchSAMLProviders(ctx, client)
	data.OIDCProviders = iamFetchOIDCProviders(ctx, client)

	// The account alias is the only human-readable name a standalone account has —
	// an org member gets its name from Organizations instead. Best-effort on the
	// same terms as the providers above.
	data.AccountAlias = iamFetchAccountAlias(ctx, client)

	return data, nil
}

// iamConvertUser maps an SDK UserDetail into the model shape. Policy documents
// stay URL-encoded (as the GAAD wire delivers them); consumers decode at use.
func iamConvertUser(u iamtypes.UserDetail) model.UserDetail {
	out := model.UserDetail{
		Arn:                 aws.ToString(u.Arn),
		Path:                aws.ToString(u.Path),
		UserId:              aws.ToString(u.UserId),
		UserName:            aws.ToString(u.UserName),
		GroupList:           u.GroupList,
		AttachedManagedPols: iamConvertAttachedPolicies(u.AttachedManagedPolicies),
		UserPolicyList:      iamConvertInlinePolicies(u.UserPolicyList),
		Tags:                iamConvertTags(u.Tags),
	}
	if u.PermissionsBoundary != nil {
		out.PermissionsBoundary = &model.PermBoundary{
			PermissionsBoundaryArn:  aws.ToString(u.PermissionsBoundary.PermissionsBoundaryArn),
			PermissionsBoundaryType: string(u.PermissionsBoundary.PermissionsBoundaryType),
		}
	}
	return out
}

// iamConvertGroup maps an SDK GroupDetail into the model shape.
func iamConvertGroup(g iamtypes.GroupDetail) model.GroupDetail {
	return model.GroupDetail{
		Arn:                 aws.ToString(g.Arn),
		Path:                aws.ToString(g.Path),
		GroupId:             aws.ToString(g.GroupId),
		GroupName:           aws.ToString(g.GroupName),
		AttachedManagedPols: iamConvertAttachedPolicies(g.AttachedManagedPolicies),
		GroupPolicyList:     iamConvertInlinePolicies(g.GroupPolicyList),
	}
}

// iamConvertRole maps an SDK RoleDetail into the model shape.
func iamConvertRole(r iamtypes.RoleDetail) model.RoleDetail {
	out := model.RoleDetail{
		Arn:                      aws.ToString(r.Arn),
		Path:                     aws.ToString(r.Path),
		RoleId:                   aws.ToString(r.RoleId),
		RoleName:                 aws.ToString(r.RoleName),
		AssumeRolePolicyDocument: aws.ToString(r.AssumeRolePolicyDocument),
		AttachedManagedPols:      iamConvertAttachedPolicies(r.AttachedManagedPolicies),
		RolePolicyList:           iamConvertInlinePolicies(r.RolePolicyList),
		InstanceProfileList:      iamConvertInstanceProfiles(r.InstanceProfileList),
		Tags:                     iamConvertTags(r.Tags),
	}
	if r.PermissionsBoundary != nil {
		out.PermissionsBoundary = &model.PermBoundary{
			PermissionsBoundaryArn:  aws.ToString(r.PermissionsBoundary.PermissionsBoundaryArn),
			PermissionsBoundaryType: string(r.PermissionsBoundary.PermissionsBoundaryType),
		}
	}
	return out
}

// iamConvertManagedPolicy maps an SDK ManagedPolicyDetail into the model shape.
func iamConvertManagedPolicy(p iamtypes.ManagedPolicyDetail) model.PolicyDetail {
	return model.PolicyDetail{
		Arn:              aws.ToString(p.Arn),
		Path:             aws.ToString(p.Path),
		PolicyId:         aws.ToString(p.PolicyId),
		PolicyName:       aws.ToString(p.PolicyName),
		DefaultVersionId: aws.ToString(p.DefaultVersionId),
		PolicyVersions:   iamConvertPolicyVersions(p.PolicyVersionList),
		AttachmentCount:  int(aws.ToInt32(p.AttachmentCount)),
	}
}

// mapSlice converts a slice by applying f to each element, returning nil for an
// empty input so an absent GAAD list stays absent (nil, not an empty non-nil
// slice) — preserving the None/[] distinction the downstream parsers rely on.
func mapSlice[I, O any](in []I, f func(I) O) []O {
	if len(in) == 0 {
		return nil
	}
	out := make([]O, 0, len(in))
	for _, v := range in {
		out = append(out, f(v))
	}
	return out
}

func iamConvertAttachedPolicies(in []iamtypes.AttachedPolicy) []model.AttachedPolicy {
	return mapSlice(in, func(p iamtypes.AttachedPolicy) model.AttachedPolicy {
		return model.AttachedPolicy{
			PolicyName: aws.ToString(p.PolicyName),
			PolicyArn:  aws.ToString(p.PolicyArn),
		}
	})
}

func iamConvertInlinePolicies(in []iamtypes.PolicyDetail) []model.InlinePolicy {
	return mapSlice(in, func(p iamtypes.PolicyDetail) model.InlinePolicy {
		return model.InlinePolicy{
			PolicyName:     aws.ToString(p.PolicyName),
			PolicyDocument: aws.ToString(p.PolicyDocument),
		}
	})
}

func iamConvertInstanceProfiles(in []iamtypes.InstanceProfile) []model.InstanceProfile {
	return mapSlice(in, func(p iamtypes.InstanceProfile) model.InstanceProfile {
		return model.InstanceProfile{
			Arn:                 aws.ToString(p.Arn),
			InstanceProfileName: aws.ToString(p.InstanceProfileName),
			InstanceProfileId:   aws.ToString(p.InstanceProfileId),
		}
	})
}

func iamConvertPolicyVersions(in []iamtypes.PolicyVersion) []model.PolicyVersion {
	return mapSlice(in, func(v iamtypes.PolicyVersion) model.PolicyVersion {
		return model.PolicyVersion{
			Document:         aws.ToString(v.Document),
			VersionId:        aws.ToString(v.VersionId),
			IsDefaultVersion: v.IsDefaultVersion,
		}
	})
}

func iamConvertTags(in []iamtypes.Tag) []model.Tag {
	return mapSlice(in, func(t iamtypes.Tag) model.Tag {
		return model.Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)}
	})
}

// iamFetchSAMLProviders enumerates SAML identity providers (ListSAMLProviders).
// model.SAMLProvider carries only the ARN, so the per-provider GetSAMLProvider
// enrichment the Python collector performs (CreateDate/ValidUntil/Tags) has no
// destination here and is skipped; the ARN alone establishes enumeration. Errors
// are swallowed (best-effort) so a missing iam:ListSAMLProviders permission does
// not fail the whole IAM collection.
func iamFetchSAMLProviders(ctx context.Context, client *iam.Client) []model.SAMLProvider {
	listed, err := client.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil
	}
	providers := make([]model.SAMLProvider, 0, len(listed.SAMLProviderList))
	for _, entry := range listed.SAMLProviderList {
		arn := aws.ToString(entry.Arn)
		if arn == "" {
			continue
		}
		providers = append(providers, model.SAMLProvider{Arn: arn})
	}
	return providers
}

// iamFetchAccountAlias returns the account's IAM alias, or "" when the account has
// none or the caller lacks iam:ListAccountAliases. An account can hold at most one
// alias, so the list needs no pagination. Best-effort like the provider fetchers: a
// missing permission degrades to an unnamed account rather than failing the whole
// IAM collection.
func iamFetchAccountAlias(ctx context.Context, client *iam.Client) string {
	listed, err := client.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil || len(listed.AccountAliases) == 0 {
		return ""
	}
	return listed.AccountAliases[0]
}

// iamFetchOIDCProviders enumerates OIDC identity providers
// (ListOpenIDConnectProviders returns only ARNs) and calls
// GetOpenIDConnectProvider per provider to populate Url/ClientIDList/
// ThumbprintList, which model.OIDCProvider carries and the node parser needs. A
// per-provider Get failure still yields a provider record with just its ARN (the
// node parser derives the url from the ARN), matching the Python collector.
func iamFetchOIDCProviders(ctx context.Context, client *iam.Client) []model.OIDCProvider {
	listed, err := client.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil
	}
	providers := make([]model.OIDCProvider, 0, len(listed.OpenIDConnectProviderList))
	for _, entry := range listed.OpenIDConnectProviderList {
		arn := aws.ToString(entry.Arn)
		if arn == "" {
			continue
		}
		record := model.OIDCProvider{Arn: arn}
		if detail, err := client.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: aws.String(arn),
		}); err == nil {
			record.Url = aws.ToString(detail.Url)
			record.ClientIDList = detail.ClientIDList
			record.ThumbprintList = detail.ThumbprintList
		}
		providers = append(providers, record)
	}
	return providers
}
