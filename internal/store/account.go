package store

import (
	"sort"
	"sync"

	"github.com/AWSHound/AWSHound/internal/model"
)

// Account holds one AWS account's collected data, keyed by ARN. Resource maps
// for other services (S3, KMS, ...) are added alongside their collectors.
type Account struct {
	// store is the owning Store, for lookups that span accounts — an account's
	// org-registered name is collected on a different account than the one it names.
	store *Store

	ID string

	// Alias is the account's IAM alias, when one was collected from this account's
	// own GAAD payload. It is a standalone account's only name source. An org member
	// may have both an alias and an org-registered name; ResolvedName ranks them.
	Alias string

	mu              sync.RWMutex
	Users           map[string]*model.UserDetail
	Groups          map[string]*model.GroupDetail
	Roles           map[string]*model.RoleDetail
	ManagedPolicies map[string]*model.PolicyDetail
	SAMLProviders   map[string]*model.SAMLProvider
	OIDCProviders   map[string]*model.OIDCProvider

	// resources holds non-IAM service resources: service -> arn -> *model.X.
	// Per-service files (store/<svc>.go) add typed accessors over this bag, so a
	// new service never edits this shared struct — keeping the collector fan-out
	// parallel-safe.
	resources map[string]map[string]any
}

func newAccount(st *Store, id string) *Account {
	return &Account{
		store:           st,
		ID:              id,
		Users:           make(map[string]*model.UserDetail),
		Groups:          make(map[string]*model.GroupDetail),
		Roles:           make(map[string]*model.RoleDetail),
		ManagedPolicies: make(map[string]*model.PolicyDetail),
		SAMLProviders:   make(map[string]*model.SAMLProvider),
		OIDCProviders:   make(map[string]*model.OIDCProvider),
		resources:       make(map[string]map[string]any),
	}
}

// AddAuthDetails ingests a GAAD response into the given account and interns every
// principal/policy/provider ARN into the shared ARN universe. Mirrors AWSHound's
// Store.ingest_iam, but in memory.
func (s *Store) AddAuthDetails(accountID string, gaad *model.AuthDetails) {
	acct := s.Account(accountID)
	acct.mu.Lock()
	defer acct.mu.Unlock()

	if gaad.AccountAlias != "" {
		acct.Alias = gaad.AccountAlias
	}

	for i := range gaad.UserDetailList {
		u := &gaad.UserDetailList[i]
		acct.Users[u.Arn] = u
		s.arn.Intern(u.Arn)
	}
	for i := range gaad.GroupDetailList {
		g := &gaad.GroupDetailList[i]
		acct.Groups[g.Arn] = g
		s.arn.Intern(g.Arn)
	}
	for i := range gaad.RoleDetailList {
		r := &gaad.RoleDetailList[i]
		acct.Roles[r.Arn] = r
		s.arn.Intern(r.Arn)
	}
	for i := range gaad.Policies {
		p := &gaad.Policies[i]
		p.KeepDefaultVersionOnly()
		acct.ManagedPolicies[p.Arn] = p
		s.arn.Intern(p.Arn)
	}
	for i := range gaad.SAMLProviders {
		sp := &gaad.SAMLProviders[i]
		acct.SAMLProviders[sp.Arn] = sp
		s.arn.Intern(sp.Arn)
	}
	for i := range gaad.OIDCProviders {
		op := &gaad.OIDCProviders[i]
		acct.OIDCProviders[op.Arn] = op
		s.arn.Intern(op.Arn)
	}
}

// ResolvedName returns the account's human-readable name, or "" when none is
// known. The org-registered name outranks the account's own IAM alias: it is the
// label the org administrator assigned, it is the one every account in the org
// agrees on, and unlike an alias it exists for members that were never collected.
//
// Ranking here, rather than letting the graph merge pick a winner, is deliberate.
// The same node id is written both by the named account's own AccountRootNode and
// by the management account's OrganizationsNodes, and MergeNodes is later-wins over
// accounts sorted by id — so a merge-decided winner would depend on whether the
// member's account id happens to sort after the management account's. Resolving
// from one store-wide answer makes both writers emit the same name.
func (a *Account) ResolvedName() string {
	if a.store != nil {
		if name := a.store.orgAccountName(a.ID); name != "" {
			return name
		}
	}
	return a.Alias
}

// PrincipalARNs returns every user + role + group ARN in the account.
func (a *Account) PrincipalARNs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.Users)+len(a.Roles)+len(a.Groups))
	for arn := range a.Users {
		out = append(out, arn)
	}
	for arn := range a.Roles {
		out = append(out, arn)
	}
	for arn := range a.Groups {
		out = append(out, arn)
	}
	return out
}

// PutResource stores a non-IAM service resource (keyed by service and ARN) in the
// account's generic resource bag. Per-service files wrap this with typed setters.
func (a *Account) PutResource(service, arn string, v any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.resources[service]
	if m == nil {
		m = make(map[string]any)
		a.resources[service] = m
	}
	m[arn] = v
}

// Resources returns a snapshot of a service's resources (arn -> value). Per-service
// files wrap this with typed getters that assert the concrete resource type.
func (a *Account) Resources(service string) map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	src := a.resources[service]
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// listResources returns the account's *T resources stored under the given service
// bag, ordered by bag key (the resource ARN) so callers emit diff-stable output.
// Values of a different concrete type sharing the bag are skipped by the type
// assertion, so a service that stores several resource kinds under one key space
// (CloudFormation stacks + StackSets, SSM parameters + managed instances) still
// gets a clean per-type list. Per-service files wrap this as their typed accessors.
func listResources[T any](a *Account, service string) []*T {
	src := a.Resources(service)
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*T, 0, len(src))
	for _, k := range keys {
		if v, ok := src[k].(*T); ok {
			out = append(out, v)
		}
	}
	return out
}
