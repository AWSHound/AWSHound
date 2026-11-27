package metrics

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/AWSHound/AWSHound/internal/apireq"
)

// The JSON shape written to disk. Kept separate from the accumulation structs so
// maps become stably-ordered slices and a troubleshooting summary is derived.
type report struct {
	StartedUnix  int64          `json:"startedUnix"`
	TotalMillis  int64          `json:"totalMillis"`
	Environment  Environment    `json:"environment"`
	Counters     counters       `json:"counters"`
	Stages       []stageTiming  `json:"stages"`
	EdgeFamilies []stageTiming  `json:"edgeFamilies,omitempty"`
	Accounts     []account      `json:"accounts"`
	AWSApi       *apireq.Report `json:"awsApi,omitempty"`
	Summary      summary        `json:"summary"`
}

type counters struct {
	Accounts     int `json:"accounts"`
	CollectUnits int `json:"collectUnits"`
	Nodes        int `json:"nodes"`
	Edges        int `json:"edges"`
}

type account struct {
	AccountID       string    `json:"accountID"`
	Profile         string    `json:"profile"`
	Regions         int       `json:"regions"`
	BootstrapMillis int64     `json:"bootstrapMillis"`
	Services        []service `json:"services"`
}

type service struct {
	Name                string `json:"name"`
	Millis              int64  `json:"millis"`
	Error               string `json:"error,omitempty"`
	RegionCount         int    `json:"regionCount,omitempty"`
	SlowestRegion       string `json:"slowestRegion,omitempty"`
	SlowestRegionMillis int64  `json:"slowestRegionMillis,omitempty"`
}

// summary surfaces the single slowest item at each granularity so a reader can
// jump straight to the bottleneck of a long run.
type summary struct {
	SlowestStage   *named        `json:"slowestStage,omitempty"`
	SlowestAccount *namedAccount `json:"slowestAccount,omitempty"`
	SlowestService *namedService `json:"slowestService,omitempty"`
	SlowestRegion  *namedRegion  `json:"slowestRegion,omitempty"`
}

type named struct {
	Name   string `json:"name"`
	Millis int64  `json:"millis"`
}
type namedAccount struct {
	AccountID string `json:"accountID"`
	Millis    int64  `json:"millis"` // bootstrap + all services
}
type namedService struct {
	AccountID string `json:"accountID"`
	Service   string `json:"service"`
	Millis    int64  `json:"millis"`
}
type namedRegion struct {
	AccountID string `json:"accountID"`
	Service   string `json:"service"`
	Region    string `json:"region"`
	Millis    int64  `json:"millis"`
}

// WriteJSON writes the accumulated metrics to path. Nil-safe: a nil receiver
// writes nothing and returns nil.
func (m *RunMetrics) WriteJSON(path string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	r := m.buildReportLocked()
	m.mu.Unlock()

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// buildReportLocked assembles the serializable report and its summary; caller
// holds mu.
func (m *RunMetrics) buildReportLocked() report {
	r := report{
		StartedUnix: m.started.Unix(),
		TotalMillis: time.Since(m.started).Milliseconds(),
		Environment: m.env,
		Counters: counters{
			Accounts:     m.accountsCount,
			CollectUnits: m.collectUnits,
			Nodes:        m.nodes,
			Edges:        m.edges,
		},
		Stages:       m.stages,
		EdgeFamilies: m.edgeFamilies,
		AWSApi:       m.apiReport,
	}

	var sum summary
	for _, st := range m.stages {
		if sum.SlowestStage == nil || st.Millis > sum.SlowestStage.Millis {
			sum.SlowestStage = &named{Name: st.Name, Millis: st.Millis}
		}
	}

	ids := append([]string(nil), m.acctOrder...)
	sort.Strings(ids)
	for _, id := range ids {
		am := m.accounts[id]
		acct := account{
			AccountID:       am.AccountID,
			Profile:         am.Profile,
			Regions:         am.Regions,
			BootstrapMillis: am.BootstrapMillis,
		}
		acctTotal := am.BootstrapMillis

		names := append([]string(nil), am.svcOrder...)
		sort.Strings(names)
		for _, name := range names {
			sm := am.services[name]
			acct.Services = append(acct.Services, service{
				Name:                name,
				Millis:              sm.Millis,
				Error:               sm.Err,
				RegionCount:         sm.RegionCount,
				SlowestRegion:       sm.SlowestRegion,
				SlowestRegionMillis: sm.SlowestRegionMillis,
			})
			acctTotal += sm.Millis
			if sum.SlowestService == nil || sm.Millis > sum.SlowestService.Millis {
				sum.SlowestService = &namedService{AccountID: id, Service: name, Millis: sm.Millis}
			}
			if sm.SlowestRegion != "" && (sum.SlowestRegion == nil || sm.SlowestRegionMillis > sum.SlowestRegion.Millis) {
				sum.SlowestRegion = &namedRegion{AccountID: id, Service: name, Region: sm.SlowestRegion, Millis: sm.SlowestRegionMillis}
			}
		}

		if sum.SlowestAccount == nil || acctTotal > sum.SlowestAccount.Millis {
			sum.SlowestAccount = &namedAccount{AccountID: id, Millis: acctTotal}
		}
		r.Accounts = append(r.Accounts, acct)
	}

	r.Summary = sum
	return r
}
