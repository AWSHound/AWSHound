// Package store is awshound's in-memory account/graph data model. It replaces
// AWSHound's DuckDB-backed AccountDataStore: that database existed largely to
// share collected state across ProcessPoolExecutor workers, which the Go
// rewrite's goroutine model makes unnecessary. One *Store is shared by all
// goroutines; per-account work is sharded without copying.
//
// Access patterns here are point lookups by ARN, per-account grouping, and
// ARN-pattern → set resolution (see ArnIndex) — map/bitmap shaped, not
// relational, so no embedded SQL engine is needed. The store holds only the
// collected identity/resource data (bounded by org IAM size); the graph itself is
// built downstream as in-memory []*graph.Node / []*graph.Edge slices, deduped by
// (start,end,kind) in build/edges and serialized by the emit package.
package store

import (
	"sort"
	"sync"
)

// Store holds all collected data, keyed by account. Safe for concurrent use.
type Store struct {
	mu       sync.RWMutex
	accounts map[string]*Account
	arn      *ArnIndex

	// orgAccountNames maps every account id an ingested organization described to
	// its org-registered name. It is store-wide rather than per-account because the
	// org that names an account is collected on a *different* account (the
	// management or delegated-admin account), while the named account's own node is
	// built from its own data — both need the same answer. Keeping the one answer
	// here is what makes an account's resolved name independent of which account
	// merges last. It never creates an Account entry: an org member that was not
	// itself collected has a name here and no account.
	orgAccountNames map[string]string
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		accounts:        make(map[string]*Account),
		arn:             NewArnIndex(),
		orgAccountNames: make(map[string]string),
	}
}

// Account returns the account with the given id, creating it if absent.
func (s *Store) Account(id string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, ok := s.accounts[id]
	if !ok {
		acct = newAccount(s, id)
		s.accounts[id] = acct
	}
	return acct
}

// putOrgAccountName records an org-registered account name. Empty names are
// dropped so a lookup miss and a nameless account are the same answer.
func (s *Store) putOrgAccountName(accountID, name string) {
	if accountID == "" || name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgAccountNames[accountID] = name
}

// orgAccountName returns the org-registered name for an account id, or "".
func (s *Store) orgAccountName(accountID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.orgAccountNames[accountID]
}

// Accounts returns a snapshot slice of all accounts, sorted by account id. The
// sort makes downstream output (graph node/edge order, metrics) deterministic and
// reproducible across separate runs, rather than depending on Go map iteration
// order.
func (s *Store) Accounts() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ARN returns the shared ARN universe index used by the evaluator.
func (s *Store) ARN() *ArnIndex { return s.arn }
