package store

import (
	"sort"

	"github.com/AWSHound/AWSHound/internal/model"
)

// eksService is the resource-bag key for EKS data. It matches EKSCollector.Service().
const eksService = "eks"

// eksAccessEntryKeyPrefix / eksPodIdentityKeyPrefix namespace the fallback keys for the
// rare access entry / Pod Identity association that arrives without its own ARN. They
// never collide with the real EKS ARNs (which start "arn:aws:eks:...:access-entry/" and
// "...:podidentityassociation/") or with each other, and — like SSM managed instances —
// such keys are stored but NOT interned into the ARN universe.
const (
	eksAccessEntryKeyPrefix = "eks-access-entry:"
	eksPodIdentityKeyPrefix = "eks-pod-identity:"
)

// IngestEKS stores a collected EKS payload on the given account and interns every
// resource ARN into the shared ARN universe. It is the in-memory analogue of AWSHound's
// ingest_eks (core/storage/store.py): clusters, node groups, access entries, and Pod
// Identity associations all land in the account's generic resource bag under eksService
// as distinct named types, so the typed accessors below can separate them by type.
//
// Clusters are keyed by their ARN and node groups by their nodegroupArn (dropping any
// without one, as the Python node parser does). Access entries and Pod Identity
// associations are keyed by their own ARN when present — falling back to a namespaced
// composite key (which is not interned) — since the DuckDB schema's composite primary
// keys and cluster-ARN foreign keys are a relational concern the in-memory bag does not
// reproduce.
func IngestEKS(st *Store, accountID string, data *model.EKSData) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)

	for i := range data.Clusters {
		c := &data.Clusters[i]
		if c.Arn == "" {
			continue
		}
		acct.PutResource(eksService, c.Arn, c)
		st.ARN().Intern(c.Arn)
	}

	for i := range data.NodeGroups {
		ng := &data.NodeGroups[i]
		if ng.NodegroupArn == "" {
			continue
		}
		acct.PutResource(eksService, ng.NodegroupArn, ng)
		st.ARN().Intern(ng.NodegroupArn)
	}

	for i := range data.AccessEntries {
		e := &data.AccessEntries[i]
		if e.AccessEntryArn != "" {
			acct.PutResource(eksService, e.AccessEntryArn, e)
			st.ARN().Intern(e.AccessEntryArn)
			continue
		}
		// No ARN on the entry: key by cluster+principal so it is still retrievable,
		// but keep it out of the ARN universe.
		if e.ClusterName == "" || e.PrincipalArn == "" {
			continue
		}
		acct.PutResource(eksService, eksAccessEntryKeyPrefix+e.ClusterName+"/"+e.PrincipalArn, e)
	}

	for i := range data.PodIdentityAssociations {
		p := &data.PodIdentityAssociations[i]
		if p.AssociationArn != "" {
			acct.PutResource(eksService, p.AssociationArn, p)
			st.ARN().Intern(p.AssociationArn)
			continue
		}
		if p.ClusterName == "" || p.RoleArn == "" {
			continue
		}
		acct.PutResource(eksService, eksPodIdentityKeyPrefix+p.ClusterName+"/"+p.Namespace+"/"+p.ServiceAccount, p)
	}
}

// EKSClusterList returns the EKS clusters ingested on this account, ordered by ARN so
// the node builder produces diff-stable output.
func (a *Account) EKSClusterList() []*model.EKSCluster {
	return listResources[model.EKSCluster](a, eksService)
}

// EKSNodeGroupList returns the EKS node groups ingested on this account, ordered by ARN.
// It returns every ingested node group (including orphans whose cluster failed to
// describe), matching the Python node parser, which iterates all of EKSData.NodeGroups.
func (a *Account) EKSNodeGroupList() []*model.EKSNodeGroup {
	return listResources[model.EKSNodeGroup](a, eksService)
}

// EKSAccessEntryList returns the EKS access entries ingested on this account, ordered by
// (cluster, principal) for stable output. Consumed by the EKS access-entry edges.
func (a *Account) EKSAccessEntryList() []*model.EKSAccessEntry {
	src := a.Resources(eksService)
	out := make([]*model.EKSAccessEntry, 0, len(src))
	for _, v := range src {
		if e, ok := v.(*model.EKSAccessEntry); ok {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterName != out[j].ClusterName {
			return out[i].ClusterName < out[j].ClusterName
		}
		return out[i].PrincipalArn < out[j].PrincipalArn
	})
	return out
}

// EKSPodIdentityAssociationList returns the Pod Identity associations ingested on this
// account, ordered by (cluster, role) for stable output. Consumed by the Pod Identity
// edge processor.
func (a *Account) EKSPodIdentityAssociationList() []*model.EKSPodIdentityAssociation {
	src := a.Resources(eksService)
	out := make([]*model.EKSPodIdentityAssociation, 0, len(src))
	for _, v := range src {
		if p, ok := v.(*model.EKSPodIdentityAssociation); ok {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterName != out[j].ClusterName {
			return out[i].ClusterName < out[j].ClusterName
		}
		return out[i].RoleArn < out[j].RoleArn
	})
	return out
}

// EKSClusterARNs returns the account's EKS cluster ARNs in ARN order. It ports
// get_eks_cluster_arns (core/models/_queries/eks.py), which the EKS attack-path edge
// processors iterate as the set of clusters an action can be authorized against.
func (a *Account) EKSClusterARNs() []string {
	clusters := a.EKSClusterList()
	out := make([]string, 0, len(clusters))
	for _, c := range clusters {
		out = append(out, c.Arn)
	}
	return out
}
