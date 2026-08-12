package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// EKSCollector fetches AWS EKS data (region-scoped; see the package doc). Per region,
// Fetch enumerates every cluster and then that cluster's node groups, access entries,
// and Pod Identity associations, stamping each cluster/node group with its region. A
// cluster whose DescribeCluster fails is dropped, but its node groups / access entries
// / Pod Identity associations are still collected by name.
type EKSCollector struct{}

// Service returns the collector's service identifier.
func (EKSCollector) Service() string { return "eks" }

// Fetch collects every EKS cluster (and its node groups, access entries, and Pod
// Identity associations) across the account's enabled regions. It mirrors
// EKSCollector.fetch: resolve the account id, discover regions, then per region list
// clusters and fan out the per-cluster describes, merging all resources into one
// EKSData.
func (EKSCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	perRegion, err := fanRegions(ctx, s, "eks", func(ctx context.Context, region string) model.EKSData {
		client := eks.NewFromConfig(s.regionCfg(region))

		var data model.EKSData
		clusterNames, listErr := eksListClusters(ctx, client)
		if listErr != nil {
			// Cannot list clusters here (region disabled / denied); skip the whole
			// region, matching the Python per-region on_error skip.
			return data
		}
		for _, name := range clusterNames {
			// A cluster that fails to describe is dropped (no cluster node), but its
			// dependents are still collected by name — exactly as the Python loop does.
			if cluster, ok := eksDescribeCluster(ctx, client, name, region); ok {
				data.Clusters = append(data.Clusters, cluster)
			}
			data.NodeGroups = append(data.NodeGroups, eksListAndDescribeNodeGroups(ctx, client, name, region)...)
			data.AccessEntries = append(data.AccessEntries, eksListAndDescribeAccessEntries(ctx, client, name)...)
			data.PodIdentityAssociations = append(data.PodIdentityAssociations, eksListPodIdentityAssociations(ctx, client, name)...)
		}
		return data
	})
	if err != nil {
		return nil, err
	}

	data := &model.EKSData{AccountId: accountID}
	for _, r := range perRegion {
		data.Clusters = append(data.Clusters, r.Clusters...)
		data.NodeGroups = append(data.NodeGroups, r.NodeGroups...)
		data.AccessEntries = append(data.AccessEntries, r.AccessEntries...)
		data.PodIdentityAssociations = append(data.PodIdentityAssociations, r.PodIdentityAssociations...)
	}
	return data, nil
}

// eksListClusters paginates ListClusters, returning the cluster names. A pagination
// error propagates so the caller can skip the region (the Python's un-guarded
// list_clusters inside fetch_region, which raises up to the fan-out on_error).
func eksListClusters(ctx context.Context, client *eks.Client) ([]string, error) {
	var names []string
	pager := eks.NewListClustersPaginator(client, &eks.ListClustersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		names = append(names, page.Clusters...)
	}
	return names, nil
}

// eksDescribeCluster describes one cluster, stamping the region. The bool is false on
// any error (or a nil cluster), mirroring the Python's _describe_cluster returning None.
func eksDescribeCluster(ctx context.Context, client *eks.Client, name, region string) (model.EKSCluster, bool) {
	out, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
	if err != nil || out.Cluster == nil {
		return model.EKSCluster{}, false
	}
	return eksConvertCluster(out.Cluster, region), true
}

// eksConvertCluster maps an SDK cluster to the collected model shape, stamping the
// region the Python collector injects and flattening the OIDC issuer.
func eksConvertCluster(c *ekstypes.Cluster, region string) model.EKSCluster {
	out := model.EKSCluster{
		Arn:             aws.ToString(c.Arn),
		Name:            aws.ToString(c.Name),
		Region:          region,
		Status:          string(c.Status),
		Version:         aws.ToString(c.Version),
		RoleArn:         aws.ToString(c.RoleArn),
		Endpoint:        aws.ToString(c.Endpoint),
		PlatformVersion: aws.ToString(c.PlatformVersion),
		Tags:            c.Tags,
		CreatedAt:       formatTime(c.CreatedAt),
	}
	if c.Identity != nil && c.Identity.Oidc != nil {
		out.Identity.Oidc.Issuer = aws.ToString(c.Identity.Oidc.Issuer)
	}
	return out
}

// eksListAndDescribeNodeGroups lists and describes every node group for a cluster,
// stamping the region. A list-pagination error stops enumeration for this cluster
// (returning what was gathered); a describe error skips just that node group — the
// Python's _list_and_describe_node_groups try/except structure.
func eksListAndDescribeNodeGroups(ctx context.Context, client *eks.Client, clusterName, region string) []model.EKSNodeGroup {
	var out []model.EKSNodeGroup
	pager := eks.NewListNodegroupsPaginator(client, &eks.ListNodegroupsInput{ClusterName: aws.String(clusterName)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, ngName := range page.Nodegroups {
			resp, derr := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   aws.String(clusterName),
				NodegroupName: aws.String(ngName),
			})
			if derr != nil || resp.Nodegroup == nil {
				continue
			}
			out = append(out, eksConvertNodeGroup(resp.Nodegroup, region))
		}
	}
	return out
}

// eksConvertNodeGroup maps an SDK node group to the collected model shape. A nil
// ScalingConfig leaves the zero-value sizing (0/0/0), matching the node parser's
// scalingConfig.get(..., 0) default.
func eksConvertNodeGroup(ng *ekstypes.Nodegroup, region string) model.EKSNodeGroup {
	out := model.EKSNodeGroup{
		NodegroupArn:  aws.ToString(ng.NodegroupArn),
		NodegroupName: aws.ToString(ng.NodegroupName),
		Region:        region,
		ClusterName:   aws.ToString(ng.ClusterName),
		NodeRole:      aws.ToString(ng.NodeRole),
		Status:        string(ng.Status),
		AmiType:       string(ng.AmiType),
		CapacityType:  string(ng.CapacityType),
		InstanceTypes: ng.InstanceTypes,
		Tags:          ng.Tags,
		CreatedAt:     formatTime(ng.CreatedAt),
		ModifiedAt:    formatTime(ng.ModifiedAt),
	}
	if ng.ScalingConfig != nil {
		out.ScalingConfig = model.EKSScalingConfig{
			MinSize:     int(aws.ToInt32(ng.ScalingConfig.MinSize)),
			MaxSize:     int(aws.ToInt32(ng.ScalingConfig.MaxSize)),
			DesiredSize: int(aws.ToInt32(ng.ScalingConfig.DesiredSize)),
		}
	}
	if ng.Resources != nil {
		resources := &model.EKSNodeGroupResources{
			AutoScalingGroups:         make([]model.EKSAutoScalingGroup, 0, len(ng.Resources.AutoScalingGroups)),
			RemoteAccessSecurityGroup: aws.ToString(ng.Resources.RemoteAccessSecurityGroup),
		}
		for _, group := range ng.Resources.AutoScalingGroups {
			resources.AutoScalingGroups = append(resources.AutoScalingGroups, model.EKSAutoScalingGroup{
				Name: aws.ToString(group.Name),
			})
		}
		out.Resources = resources
	}
	return out
}

// eksListAndDescribeAccessEntries lists and describes every access entry for a cluster,
// enriching each with its associated access policies. A list error stops enumeration
// for this cluster; a describe error skips just that entry — the Python's
// _list_and_describe_access_entries try/except structure.
func eksListAndDescribeAccessEntries(ctx context.Context, client *eks.Client, clusterName string) []model.EKSAccessEntry {
	var out []model.EKSAccessEntry
	pager := eks.NewListAccessEntriesPaginator(client, &eks.ListAccessEntriesInput{ClusterName: aws.String(clusterName)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, principalArn := range page.AccessEntries {
			resp, derr := client.DescribeAccessEntry(ctx, &eks.DescribeAccessEntryInput{
				ClusterName:  aws.String(clusterName),
				PrincipalArn: aws.String(principalArn),
			})
			if derr != nil || resp.AccessEntry == nil {
				continue
			}
			entry := eksConvertAccessEntry(resp.AccessEntry)
			entry.AccessPolicies = eksListAssociatedAccessPolicies(ctx, client, clusterName, principalArn)
			out = append(out, entry)
		}
	}
	return out
}

// eksConvertAccessEntry maps an SDK access entry to the collected model shape (the
// AccessPolicies enrichment is filled in by the caller).
func eksConvertAccessEntry(e *ekstypes.AccessEntry) model.EKSAccessEntry {
	return model.EKSAccessEntry{
		ClusterName:      aws.ToString(e.ClusterName),
		PrincipalArn:     aws.ToString(e.PrincipalArn),
		AccessEntryArn:   aws.ToString(e.AccessEntryArn),
		Type:             aws.ToString(e.Type),
		Username:         aws.ToString(e.Username),
		KubernetesGroups: e.KubernetesGroups,
		CreatedAt:        formatTime(e.CreatedAt),
		ModifiedAt:       formatTime(e.ModifiedAt),
		Tags:             e.Tags,
	}
}

// eksListAssociatedAccessPolicies paginates the access policies bound to an access
// entry. It always returns a non-nil slice (empty on error), matching the Python's
// accessPolicies = [] fallback.
func eksListAssociatedAccessPolicies(ctx context.Context, client *eks.Client, clusterName, principalArn string) []model.EKSAssociatedAccessPolicy {
	out := []model.EKSAssociatedAccessPolicy{}
	pager := eks.NewListAssociatedAccessPoliciesPaginator(client, &eks.ListAssociatedAccessPoliciesInput{
		ClusterName:  aws.String(clusterName),
		PrincipalArn: aws.String(principalArn),
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for i := range page.AssociatedAccessPolicies {
			p := page.AssociatedAccessPolicies[i]
			ap := model.EKSAssociatedAccessPolicy{
				PolicyArn:    aws.ToString(p.PolicyArn),
				AssociatedAt: formatTime(p.AssociatedAt),
				ModifiedAt:   formatTime(p.ModifiedAt),
			}
			if p.AccessScope != nil {
				ap.AccessScope = model.EKSAccessScope{
					Type:       string(p.AccessScope.Type),
					Namespaces: p.AccessScope.Namespaces,
				}
			}
			out = append(out, ap)
		}
	}
	return out
}

// eksListPodIdentityAssociations lists the Pod Identity associations for a cluster and
// describes each by id. Pod Identity is not available in every region/cluster, so a
// list error is swallowed (returning what was gathered) and a describe error skips just
// that association — the Python's _list_pod_identity_associations behavior.
func eksListPodIdentityAssociations(ctx context.Context, client *eks.Client, clusterName string) []model.EKSPodIdentityAssociation {
	var out []model.EKSPodIdentityAssociation
	pager := eks.NewListPodIdentityAssociationsPaginator(client, &eks.ListPodIdentityAssociationsInput{ClusterName: aws.String(clusterName)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, summary := range page.Associations {
			assocID := aws.ToString(summary.AssociationId)
			if assocID == "" {
				continue
			}
			resp, derr := client.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
				ClusterName:   aws.String(clusterName),
				AssociationId: aws.String(assocID),
			})
			if derr != nil || resp.Association == nil {
				continue
			}
			out = append(out, eksConvertPodIdentityAssociation(resp.Association))
		}
	}
	return out
}

// eksConvertPodIdentityAssociation maps an SDK Pod Identity association to the
// collected model shape.
func eksConvertPodIdentityAssociation(a *ekstypes.PodIdentityAssociation) model.EKSPodIdentityAssociation {
	return model.EKSPodIdentityAssociation{
		ClusterName:    aws.ToString(a.ClusterName),
		Namespace:      aws.ToString(a.Namespace),
		ServiceAccount: aws.ToString(a.ServiceAccount),
		RoleArn:        aws.ToString(a.RoleArn),
		AssociationArn: aws.ToString(a.AssociationArn),
		AssociationId:  aws.ToString(a.AssociationId),
		CreatedAt:      formatTime(a.CreatedAt),
		ModifiedAt:     formatTime(a.ModifiedAt),
		Tags:           a.Tags,
	}
}
