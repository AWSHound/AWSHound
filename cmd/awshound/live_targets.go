package main

import (
	"context"
	"fmt"

	"github.com/AWSHound/AWSHound/internal/apireq"
	"github.com/AWSHound/AWSHound/internal/collect"
	"github.com/AWSHound/AWSHound/internal/progress"
)

// buildLiveTargets resolves the accounts a live run will collect from the three
// auth sources, returning one accountTarget per account for bootstrapAccounts.
//
//   - With --org-role set, it enumerates the AWS Organization from a base identity
//     (the first --profile, else the ambient/default credential chain) and returns
//     the management account plus one assume-role target per active child.
//   - Otherwise it returns one target per selected profile: the explicit --profile
//     names merged with the --aws-config bloodhound_collect profiles.
//
// names is the run's collector set; org-role child accounts drop the organizations
// collector because organization data is collected once, from the management
// account (mirroring the Python CLI, where a child can't enumerate the org anyway).
func buildLiveTargets(ctx context.Context, profiles []string, orgRole, awsConfig, awsCreds string, regions, names []string, reporter progress.Reporter, controllers ...*apireq.Controller) ([]accountTarget, error) {
	if orgRole != "" {
		return orgRoleTargets(ctx, profiles, orgRole, awsConfig, awsCreds, regions, names, reporter, controllers...)
	}
	selected := selectProfiles(profiles, awsConfig)
	if len(selected) == 0 {
		return nil, fmt.Errorf("no accounts to collect: pass --profile, or --aws-config with a section that sets bloodhound_collect = true")
	}
	targets := make([]accountTarget, 0, len(selected))
	for _, p := range selected {
		p := p
		targets = append(targets, accountTarget{
			label:      p,
			collectors: names,
			newSession: func(ctx context.Context, region string) (*collect.Session, error) {
				return collect.NewSessionFromFiles(ctx, p, region, awsConfig, awsCreds, controllers...)
			},
		})
	}
	return targets, nil
}

// orgRoleTargets drives the --org-role sweep: it builds a base session from the
// base identity (first --profile, else the default chain honoring --aws-config /
// --aws-credentials), enumerates the organization, and returns the management
// account (collected directly) plus one assume-role target per child. The org
// discovery runs here, before the Bootstrap stage, so a discovery failure (e.g. a
// non-management base identity denied organizations:ListAccounts) aborts the run
// with a clear error rather than silently collecting nothing.
func orgRoleTargets(ctx context.Context, profiles []string, orgRole, awsConfig, awsCreds string, regions, names []string, reporter progress.Reporter, controllers ...*apireq.Controller) ([]accountTarget, error) {
	base := ""
	if len(profiles) > 0 {
		base = profiles[0]
		if len(profiles) > 1 {
			reporter.Log(fmt.Sprintf("org-role: using profile %q as the base identity; the other --profile value(s) are ignored for the org sweep", base))
		}
	}
	region := "us-east-1"
	if len(regions) > 0 {
		region = regions[0]
	}
	baseSess, err := collect.NewSessionFromFiles(ctx, base, region, awsConfig, awsCreds, controllers...)
	if err != nil {
		return nil, err
	}
	reporter.Log("org-role: discovering organization accounts…")
	mgmtID, childIDs, err := collect.ListOrgAccounts(ctx, baseSess)
	if err != nil {
		return nil, fmt.Errorf("org-role: discover organization accounts: %w", err)
	}
	reporter.Log(fmt.Sprintf("org-role: management account %s + %d child account(s); assuming role %q into each child", mgmtID, len(childIDs), orgRole))

	targets := make([]accountTarget, 0, len(childIDs)+1)
	// Management account: collect directly with the base identity — it keeps the
	// organizations collector, so org data is gathered exactly once, here.
	targets = append(targets, accountTarget{
		label:      mgmtID,
		collectors: names,
		newSession: func(ctx context.Context, region string) (*collect.Session, error) {
			return collect.NewSessionFromFiles(ctx, base, region, awsConfig, awsCreds, controllers...)
		},
	})
	// Child accounts: assume orgRole into each. baseSess is reused purely as the
	// credential/config template — NewAssumeRoleSession copies its config and swaps
	// in the assumed credentials without mutating it, so it safely backs every
	// child session, including the concurrent bootstrap goroutines.
	childCollectors := withoutCollector(names, "organizations")
	for _, id := range childIDs {
		id := id
		targets = append(targets, accountTarget{
			label:      id,
			collectors: childCollectors,
			newSession: func(ctx context.Context, region string) (*collect.Session, error) {
				return collect.NewAssumeRoleSession(baseSess, id, orgRole, region)
			},
		})
	}
	return targets, nil
}

// selectProfiles merges the explicit --profile names with the profiles opted in
// via bloodhound_collect = true in the --aws-config file (when given), preserving
// first-seen order and dropping duplicates. Either source may be empty.
func selectProfiles(explicit []string, awsConfig string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range explicit {
		add(p)
	}
	if awsConfig != "" {
		for _, p := range profilesFromConfig(awsConfig) {
			add(p)
		}
	}
	return out
}

// withoutCollector returns names with drop removed (order preserved). Used to keep
// the organizations collector off org-role child accounts.
func withoutCollector(names []string, drop string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != drop {
			out = append(out, n)
		}
	}
	return out
}
