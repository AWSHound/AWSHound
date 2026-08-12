// Code generated from AWSHound schema.json. DO NOT EDIT BY HAND.
// Regenerate with scratchpad/gen_kinds.py after schema changes.

package graph

// NodeKind is the OpenGraph kind label for a node.
type NodeKind string

// EdgeKind is the OpenGraph kind label for a relationship.
type EdgeKind string

// Node kinds (20).
const (
	KindOrganization           NodeKind = "AWS_Organization"
	KindAccount                NodeKind = "AWS_Account"
	KindUser                   NodeKind = "AWS_User"
	KindGroup                  NodeKind = "AWS_Group"
	KindRole                   NodeKind = "AWS_Role"
	KindPolicy                 NodeKind = "AWS_Policy"
	KindServiceControlPolicy   NodeKind = "AWS_ServiceControlPolicy"
	KindResourceControlPolicy  NodeKind = "AWS_ResourceControlPolicy"
	KindS3Bucket               NodeKind = "AWS_S3Bucket"
	KindS3Object               NodeKind = "AWS_S3Object"
	KindCloudFormationStack    NodeKind = "AWS_CloudFormationStack"
	KindCloudFormationStackSet NodeKind = "AWS_CloudFormationStackSet"
	KindSAMLProvider           NodeKind = "AWS_SAMLProvider"
	KindOIDCProvider           NodeKind = "AWS_OIDCProvider"
	KindEC2Instance            NodeKind = "AWS_EC2Instance"
	KindEKSCluster             NodeKind = "AWS_EKSCluster"
	KindEKSNodeGroup           NodeKind = "AWS_EKSNodeGroup"
	KindKMSKey                 NodeKind = "AWS_KMSKey"
	KindLambdaFunction         NodeKind = "AWS_LambdaFunction"
	KindSSMParameter           NodeKind = "AWS_SSMParameter"
)

// Edge (relationship) kinds (156).
const (
	KindContains                                EdgeKind = "AWS_Contains"
	KindMemberOf                                EdgeKind = "AWS_MemberOf"
	KindHasPolicy                               EdgeKind = "AWS_HasPolicy"
	KindHasMember                               EdgeKind = "AWS_HasMember"
	KindHasSCP                                  EdgeKind = "AWS_HasSCP"
	KindHasRCP                                  EdgeKind = "AWS_HasRCP"
	KindAttachedTo                              EdgeKind = "AWS_AttachedTo"
	KindTrusts                                  EdgeKind = "AWS_Trusts"
	KindTrustedBy                               EdgeKind = "AWS_TrustedBy"
	KindTrustsSAMLProvider                      EdgeKind = "AWS_TrustsSAMLProvider"
	KindTrustsOIDCProvider                      EdgeKind = "AWS_TrustsOIDCProvider"
	KindRunsAs                                  EdgeKind = "AWS_RunsAs"
	KindCanSetDefaultPolicyVersion              EdgeKind = "AWS_CanSetDefaultPolicyVersion"
	KindCanCreatePolicyVersion                  EdgeKind = "AWS_CanCreatePolicyVersion"
	KindCanAttachUserPolicy                     EdgeKind = "AWS_CanAttachUserPolicy"
	KindCanAttachGroupPolicy                    EdgeKind = "AWS_CanAttachGroupPolicy"
	KindCanAttachRolePolicy                     EdgeKind = "AWS_CanAttachRolePolicy"
	KindCanDetachUserPolicy                     EdgeKind = "AWS_CanDetachUserPolicy"
	KindCanDetachGroupPolicy                    EdgeKind = "AWS_CanDetachGroupPolicy"
	KindCanDetachRolePolicy                     EdgeKind = "AWS_CanDetachRolePolicy"
	KindCanPutUserPolicy                        EdgeKind = "AWS_CanPutUserPolicy"
	KindCanPutGroupPolicy                       EdgeKind = "AWS_CanPutGroupPolicy"
	KindCanPutRolePolicy                        EdgeKind = "AWS_CanPutRolePolicy"
	KindCanDeleteUserPolicy                     EdgeKind = "AWS_CanDeleteUserPolicy"
	KindCanDeleteGroupPolicy                    EdgeKind = "AWS_CanDeleteGroupPolicy"
	KindCanDeleteRolePolicy                     EdgeKind = "AWS_CanDeleteRolePolicy"
	KindCanUpdateSelfPolicy                     EdgeKind = "AWS_CanUpdateSelfPolicy"
	KindCanUpdateOtherPolicy                    EdgeKind = "AWS_CanUpdateOtherPolicy"
	KindCanUpdateAssumeRolePolicyAndAssume      EdgeKind = "AWS_CanUpdateAssumeRolePolicyAndAssume"
	KindCanCreateAndAssumeAdminRole             EdgeKind = "AWS_CanCreateAndAssumeAdminRole"
	KindCanCreateAndPassAdminRole               EdgeKind = "AWS_CanCreateAndPassAdminRole"
	KindCanCreateAndAccessAdminUser             EdgeKind = "AWS_CanCreateAndAccessAdminUser"
	KindCanPutUserPermissionsBoundary           EdgeKind = "AWS_CanPutUserPermissionsBoundary"
	KindCanPutRolePermissionsBoundary           EdgeKind = "AWS_CanPutRolePermissionsBoundary"
	KindCanDeleteUserPermissionsBoundary        EdgeKind = "AWS_CanDeleteUserPermissionsBoundary"
	KindCanDeleteRolePermissionsBoundary        EdgeKind = "AWS_CanDeleteRolePermissionsBoundary"
	KindCanAddUserToGroup                       EdgeKind = "AWS_CanAddUserToGroup"
	KindCanRemoveUserFromGroup                  EdgeKind = "AWS_CanRemoveUserFromGroup"
	KindCanCreateGroup                          EdgeKind = "AWS_CanCreateGroup"
	KindCanDeleteGroup                          EdgeKind = "AWS_CanDeleteGroup"
	KindCanCreateUser                           EdgeKind = "AWS_CanCreateUser"
	KindCanDeleteUser                           EdgeKind = "AWS_CanDeleteUser"
	KindCanCreateAccessKey                      EdgeKind = "AWS_CanCreateAccessKey"
	KindCanDeleteAccessKey                      EdgeKind = "AWS_CanDeleteAccessKey"
	KindCanUpdateAccessKey                      EdgeKind = "AWS_CanUpdateAccessKey"
	KindCanCreateLoginProfile                   EdgeKind = "AWS_CanCreateLoginProfile"
	KindCanUpdateLoginProfile                   EdgeKind = "AWS_CanUpdateLoginProfile"
	KindCanDeleteLoginProfile                   EdgeKind = "AWS_CanDeleteLoginProfile"
	KindCanCreateServiceSpecificCredential      EdgeKind = "AWS_CanCreateServiceSpecificCredential"
	KindCanResetServiceSpecificCredential       EdgeKind = "AWS_CanResetServiceSpecificCredential"
	KindCanDeleteServiceSpecificCredential      EdgeKind = "AWS_CanDeleteServiceSpecificCredential"
	KindCanUploadSSHPublicKey                   EdgeKind = "AWS_CanUploadSSHPublicKey"
	KindCanDeleteSSHPublicKey                   EdgeKind = "AWS_CanDeleteSSHPublicKey"
	KindCanUpdateSSHPublicKey                   EdgeKind = "AWS_CanUpdateSSHPublicKey"
	KindCanDeactivateMFADevice                  EdgeKind = "AWS_CanDeactivateMFADevice"
	KindCanDeleteVirtualMFADevice               EdgeKind = "AWS_CanDeleteVirtualMFADevice"
	KindCanResyncMFADevice                      EdgeKind = "AWS_CanResyncMFADevice"
	KindCanEnableMFADevice                      EdgeKind = "AWS_CanEnableMFADevice"
	KindCanCreateVirtualMFADevice               EdgeKind = "AWS_CanCreateVirtualMFADevice"
	KindCanUpdateAssumeRolePolicy               EdgeKind = "AWS_CanUpdateAssumeRolePolicy"
	KindCanCreateRole                           EdgeKind = "AWS_CanCreateRole"
	KindCanDeleteRole                           EdgeKind = "AWS_CanDeleteRole"
	KindHasExternalRoleTrust                    EdgeKind = "AWS_HasExternalRoleTrust"
	KindCanAssumeRole                           EdgeKind = "AWS_CanAssumeRole"
	KindCanCreateOIDCProviderAndAssumeRole      EdgeKind = "AWS_CanCreateOIDCProviderAndAssumeRole"
	KindCanCreateSAMLProviderAndAssumeRole      EdgeKind = "AWS_CanCreateSAMLProviderAndAssumeRole"
	KindCanAssumeRoleWithSAML                   EdgeKind = "AWS_CanAssumeRoleWithSAML"
	KindCanAssumeRoleWithWebIdentity            EdgeKind = "AWS_CanAssumeRoleWithWebIdentity"
	KindCanGetFederationToken                   EdgeKind = "AWS_CanGetFederationToken"
	KindCanGetSessionToken                      EdgeKind = "AWS_CanGetSessionToken"
	KindCanUpdateSAMLProvider                   EdgeKind = "AWS_CanUpdateSAMLProvider"
	KindCanCreateSAMLProvider                   EdgeKind = "AWS_CanCreateSAMLProvider"
	KindCanDeleteSAMLProvider                   EdgeKind = "AWS_CanDeleteSAMLProvider"
	KindCanUpdateOIDCProviderThumbprint         EdgeKind = "AWS_CanUpdateOIDCProviderThumbprint"
	KindCanAddClientIDToOIDCProvider            EdgeKind = "AWS_CanAddClientIDToOIDCProvider"
	KindCanRemoveClientIDFromOIDCProvider       EdgeKind = "AWS_CanRemoveClientIDFromOIDCProvider"
	KindCanCreateOIDCProvider                   EdgeKind = "AWS_CanCreateOIDCProvider"
	KindCanDeleteOIDCProvider                   EdgeKind = "AWS_CanDeleteOIDCProvider"
	KindCanAttachRolePolicyWildcard             EdgeKind = "AWS_CanAttachRolePolicyWildcard"
	KindCanPutRolePolicyWildcard                EdgeKind = "AWS_CanPutRolePolicyWildcard"
	KindCanPassRoleToService                    EdgeKind = "AWS_CanPassRoleToService"
	KindCanDeleteBucket                         EdgeKind = "AWS_CanDeleteBucket"
	KindCanDeleteBucketPolicy                   EdgeKind = "AWS_CanDeleteBucketPolicy"
	KindCanDeleteObject                         EdgeKind = "AWS_CanDeleteObject"
	KindCanGetBucketACL                         EdgeKind = "AWS_CanGetBucketACL"
	KindCanGetBucketPolicy                      EdgeKind = "AWS_CanGetBucketPolicy"
	KindCanGetObject                            EdgeKind = "AWS_CanGetObject"
	KindCanGetObjectACL                         EdgeKind = "AWS_CanGetObjectACL"
	KindCanListAllMyBuckets                     EdgeKind = "AWS_CanListAllMyBuckets"
	KindCanListBucket                           EdgeKind = "AWS_CanListBucket"
	KindCanPutAccountPublicAccessBlock          EdgeKind = "AWS_CanPutAccountPublicAccessBlock"
	KindCanPutBucketACL                         EdgeKind = "AWS_CanPutBucketACL"
	KindCanPutBucketOwnershipControls           EdgeKind = "AWS_CanPutBucketOwnershipControls"
	KindCanPutBucketPolicy                      EdgeKind = "AWS_CanPutBucketPolicy"
	KindCanPutBucketPublicAccessBlock           EdgeKind = "AWS_CanPutBucketPublicAccessBlock"
	KindCanPutObject                            EdgeKind = "AWS_CanPutObject"
	KindCanPutObjectACL                         EdgeKind = "AWS_CanPutObjectACL"
	KindS3ObjectRead                            EdgeKind = "AWS_S3ObjectRead"
	KindS3ObjectWrite                           EdgeKind = "AWS_S3ObjectWrite"
	KindS3ObjectAll                             EdgeKind = "AWS_S3ObjectAll"
	KindS3BucketRead                            EdgeKind = "AWS_S3BucketRead"
	KindS3BucketWrite                           EdgeKind = "AWS_S3BucketWrite"
	KindS3BucketAll                             EdgeKind = "AWS_S3BucketAll"
	KindCanCreateKMSGrant                       EdgeKind = "AWS_CanCreateKMSGrant"
	KindCanDecryptKMSKey                        EdgeKind = "AWS_CanDecryptKMSKey"
	KindCanDisableKMSKey                        EdgeKind = "AWS_CanDisableKMSKey"
	KindCanEncryptKMSKey                        EdgeKind = "AWS_CanEncryptKMSKey"
	KindCanGenerateKMSDataKey                   EdgeKind = "AWS_CanGenerateKMSDataKey"
	KindCanListKMSKeys                          EdgeKind = "AWS_CanListKMSKeys"
	KindCanModifyKMSKeyPolicy                   EdgeKind = "AWS_CanModifyKMSKeyPolicy"
	KindCanScheduleKMSKeyDeletion               EdgeKind = "AWS_CanScheduleKMSKeyDeletion"
	KindCanSelfGrantKMSOps                      EdgeKind = "AWS_CanSelfGrantKMSOps"
	KindKMSKeyRead                              EdgeKind = "AWS_KMSKeyRead"
	KindKMSKeyAll                               EdgeKind = "AWS_KMSKeyAll"
	KindCanCreateSSMAssociation                 EdgeKind = "AWS_CanCreateSSMAssociation"
	KindCanCreateSSMDocument                    EdgeKind = "AWS_CanCreateSSMDocument"
	KindCanStartSSMAutomationExecution          EdgeKind = "AWS_CanStartSSMAutomationExecution"
	KindCanGetParameter                         EdgeKind = "AWS_CanGetParameter"
	KindCanPutParameter                         EdgeKind = "AWS_CanPutParameter"
	KindCanDeleteParameter                      EdgeKind = "AWS_CanDeleteParameter"
	KindCanAddLambdaPermission                  EdgeKind = "AWS_CanAddLambdaPermission"
	KindCanCreateLambdaEventSource              EdgeKind = "AWS_CanCreateLambdaEventSource"
	KindCanDeleteLambdaFunction                 EdgeKind = "AWS_CanDeleteLambdaFunction"
	KindCanInvokeLambdaFunction                 EdgeKind = "AWS_CanInvokeLambdaFunction"
	KindCanRemoveLambdaPermission               EdgeKind = "AWS_CanRemoveLambdaPermission"
	KindCanUpdateLambdaCode                     EdgeKind = "AWS_CanUpdateLambdaCode"
	KindCanUpdateLambdaConfiguration            EdgeKind = "AWS_CanUpdateLambdaConfiguration"
	KindCanUpdateLambdaURLConfig                EdgeKind = "AWS_CanUpdateLambdaURLConfig"
	KindCanCreateLambdaFunction                 EdgeKind = "AWS_CanCreateLambdaFunction"
	KindLambdaFunctionWrite                     EdgeKind = "AWS_LambdaFunctionWrite"
	KindLambdaFunctionAll                       EdgeKind = "AWS_LambdaFunctionAll"
	KindCanModifyEC2InstanceAttribute           EdgeKind = "AWS_CanModifyEC2InstanceAttribute"
	KindCanAssociateIAMInstanceProfile          EdgeKind = "AWS_CanAssociateIAMInstanceProfile"
	KindCanReplaceIAMInstanceProfileAssociation EdgeKind = "AWS_CanReplaceIAMInstanceProfileAssociation"
	KindCanGetPasswordData                      EdgeKind = "AWS_CanGetPasswordData"
	KindEC2CanVolumeSwap                        EdgeKind = "AWS_EC2CanVolumeSwap"
	KindCanDisassociateIAMInstanceProfile       EdgeKind = "AWS_CanDisassociateIAMInstanceProfile"
	KindCanTerminateInstances                   EdgeKind = "AWS_CanTerminateInstances"
	KindCanCreateSnapshot                       EdgeKind = "AWS_CanCreateSnapshot"
	KindCanCreateImage                          EdgeKind = "AWS_CanCreateImage"
	KindCanRunInstances                         EdgeKind = "AWS_CanRunInstances"
	KindCanRequestSpotInstances                 EdgeKind = "AWS_CanRequestSpotInstances"
	KindSSMCanSendCommand                       EdgeKind = "AWS_SSMCanSendCommand"
	KindSSMCanStartSession                      EdgeKind = "AWS_SSMCanStartSession"
	KindCanCreateCloudFormationStack            EdgeKind = "AWS_CanCreateCloudFormationStack"
	KindCanCreateCloudFormationStackSet         EdgeKind = "AWS_CanCreateCloudFormationStackSet"
	KindCanUpdateCloudFormationStackSet         EdgeKind = "AWS_CanUpdateCloudFormationStackSet"
	KindCanUpdateCloudFormationStack            EdgeKind = "AWS_CanUpdateCloudFormationStack"
	KindCanExecuteCloudFormationChangeSet       EdgeKind = "AWS_CanExecuteCloudFormationChangeSet"
	KindClusterHasNodeGroup                     EdgeKind = "AWS_ClusterHasNodeGroup"
	KindNodeGroupHasRole                        EdgeKind = "AWS_NodeGroupHasRole"
	KindCanAssumeRoleViaIRSA                    EdgeKind = "AWS_CanAssumeRoleViaIRSA"
	KindCanAssumeRoleViaPodIdentity             EdgeKind = "AWS_CanAssumeRoleViaPodIdentity"
	KindCanCreateAndAssociateEKSAccessEntry     EdgeKind = "AWS_CanCreateAndAssociateEKSAccessEntry"
	KindCanCreateEKSNodegroup                   EdgeKind = "AWS_CanCreateEKSNodegroup"
	KindCanCreateEKSPodIdentityAssociation      EdgeKind = "AWS_CanCreateEKSPodIdentityAssociation"
)

// traversableKinds are the relationship kinds BHE treats as
// attack-path-traversable (is_traversable=true in the schema).
var traversableKinds = map[EdgeKind]bool{
	KindContains:                            true,
	KindRunsAs:                              true,
	KindCanUpdateSelfPolicy:                 true,
	KindCanUpdateOtherPolicy:                true,
	KindCanUpdateAssumeRolePolicyAndAssume:  true,
	KindCanCreateAndAssumeAdminRole:         true,
	KindCanCreateAndPassAdminRole:           true,
	KindCanCreateAndAccessAdminUser:         true,
	KindCanCreateAccessKey:                  true,
	KindCanCreateLoginProfile:               true,
	KindCanUpdateLoginProfile:               true,
	KindCanAssumeRole:                       true,
	KindCanCreateOIDCProviderAndAssumeRole:  true,
	KindCanCreateSAMLProviderAndAssumeRole:  true,
	KindCanAssumeRoleWithSAML:               true,
	KindCanAssumeRoleWithWebIdentity:        true,
	KindCanUpdateSAMLProvider:               true,
	KindCanUpdateOIDCProviderThumbprint:     true,
	KindCanPassRoleToService:                true,
	KindS3BucketAll:                         true,
	KindCanUpdateLambdaCode:                 true,
	KindCanUpdateLambdaConfiguration:        true,
	KindLambdaFunctionWrite:                 true,
	KindLambdaFunctionAll:                   true,
	KindCanModifyEC2InstanceAttribute:       true,
	KindEC2CanVolumeSwap:                    true,
	KindSSMCanSendCommand:                   true,
	KindSSMCanStartSession:                  true,
	KindCanUpdateCloudFormationStack:        true,
	KindCanExecuteCloudFormationChangeSet:   true,
	KindClusterHasNodeGroup:                 true,
	KindNodeGroupHasRole:                    true,
	KindCanAssumeRoleViaIRSA:                true,
	KindCanAssumeRoleViaPodIdentity:         true,
	KindCanCreateAndAssociateEKSAccessEntry: true,
	KindCanCreateEKSPodIdentityAssociation:  true,
}

// IsTraversable reports whether an edge kind is traversable in BHE.
func (k EdgeKind) IsTraversable() bool { return traversableKinds[k] }

// AllNodeKinds is every node kind the schema declares.
var AllNodeKinds = []NodeKind{
	KindOrganization,
	KindAccount,
	KindUser,
	KindGroup,
	KindRole,
	KindPolicy,
	KindServiceControlPolicy,
	KindResourceControlPolicy,
	KindS3Bucket,
	KindS3Object,
	KindCloudFormationStack,
	KindCloudFormationStackSet,
	KindSAMLProvider,
	KindOIDCProvider,
	KindEC2Instance,
	KindEKSCluster,
	KindEKSNodeGroup,
	KindKMSKey,
	KindLambdaFunction,
	KindSSMParameter,
}

// AllEdgeKinds is every relationship kind the schema declares.
var AllEdgeKinds = []EdgeKind{
	KindContains,
	KindMemberOf,
	KindHasPolicy,
	KindHasMember,
	KindHasSCP,
	KindHasRCP,
	KindAttachedTo,
	KindTrusts,
	KindTrustedBy,
	KindTrustsSAMLProvider,
	KindTrustsOIDCProvider,
	KindRunsAs,
	KindCanSetDefaultPolicyVersion,
	KindCanCreatePolicyVersion,
	KindCanAttachUserPolicy,
	KindCanAttachGroupPolicy,
	KindCanAttachRolePolicy,
	KindCanDetachUserPolicy,
	KindCanDetachGroupPolicy,
	KindCanDetachRolePolicy,
	KindCanPutUserPolicy,
	KindCanPutGroupPolicy,
	KindCanPutRolePolicy,
	KindCanDeleteUserPolicy,
	KindCanDeleteGroupPolicy,
	KindCanDeleteRolePolicy,
	KindCanUpdateSelfPolicy,
	KindCanUpdateOtherPolicy,
	KindCanUpdateAssumeRolePolicyAndAssume,
	KindCanCreateAndAssumeAdminRole,
	KindCanCreateAndPassAdminRole,
	KindCanCreateAndAccessAdminUser,
	KindCanPutUserPermissionsBoundary,
	KindCanPutRolePermissionsBoundary,
	KindCanDeleteUserPermissionsBoundary,
	KindCanDeleteRolePermissionsBoundary,
	KindCanAddUserToGroup,
	KindCanRemoveUserFromGroup,
	KindCanCreateGroup,
	KindCanDeleteGroup,
	KindCanCreateUser,
	KindCanDeleteUser,
	KindCanCreateAccessKey,
	KindCanDeleteAccessKey,
	KindCanUpdateAccessKey,
	KindCanCreateLoginProfile,
	KindCanUpdateLoginProfile,
	KindCanDeleteLoginProfile,
	KindCanCreateServiceSpecificCredential,
	KindCanResetServiceSpecificCredential,
	KindCanDeleteServiceSpecificCredential,
	KindCanUploadSSHPublicKey,
	KindCanDeleteSSHPublicKey,
	KindCanUpdateSSHPublicKey,
	KindCanDeactivateMFADevice,
	KindCanDeleteVirtualMFADevice,
	KindCanResyncMFADevice,
	KindCanEnableMFADevice,
	KindCanCreateVirtualMFADevice,
	KindCanUpdateAssumeRolePolicy,
	KindCanCreateRole,
	KindCanDeleteRole,
	KindHasExternalRoleTrust,
	KindCanAssumeRole,
	KindCanCreateOIDCProviderAndAssumeRole,
	KindCanCreateSAMLProviderAndAssumeRole,
	KindCanAssumeRoleWithSAML,
	KindCanAssumeRoleWithWebIdentity,
	KindCanGetFederationToken,
	KindCanGetSessionToken,
	KindCanUpdateSAMLProvider,
	KindCanCreateSAMLProvider,
	KindCanDeleteSAMLProvider,
	KindCanUpdateOIDCProviderThumbprint,
	KindCanAddClientIDToOIDCProvider,
	KindCanRemoveClientIDFromOIDCProvider,
	KindCanCreateOIDCProvider,
	KindCanDeleteOIDCProvider,
	KindCanAttachRolePolicyWildcard,
	KindCanPutRolePolicyWildcard,
	KindCanPassRoleToService,
	KindCanDeleteBucket,
	KindCanDeleteBucketPolicy,
	KindCanDeleteObject,
	KindCanGetBucketACL,
	KindCanGetBucketPolicy,
	KindCanGetObject,
	KindCanGetObjectACL,
	KindCanListAllMyBuckets,
	KindCanListBucket,
	KindCanPutAccountPublicAccessBlock,
	KindCanPutBucketACL,
	KindCanPutBucketOwnershipControls,
	KindCanPutBucketPolicy,
	KindCanPutBucketPublicAccessBlock,
	KindCanPutObject,
	KindCanPutObjectACL,
	KindS3ObjectRead,
	KindS3ObjectWrite,
	KindS3ObjectAll,
	KindS3BucketRead,
	KindS3BucketWrite,
	KindS3BucketAll,
	KindCanCreateKMSGrant,
	KindCanDecryptKMSKey,
	KindCanDisableKMSKey,
	KindCanEncryptKMSKey,
	KindCanGenerateKMSDataKey,
	KindCanListKMSKeys,
	KindCanModifyKMSKeyPolicy,
	KindCanScheduleKMSKeyDeletion,
	KindCanSelfGrantKMSOps,
	KindKMSKeyRead,
	KindKMSKeyAll,
	KindCanCreateSSMAssociation,
	KindCanCreateSSMDocument,
	KindCanStartSSMAutomationExecution,
	KindCanGetParameter,
	KindCanPutParameter,
	KindCanDeleteParameter,
	KindCanAddLambdaPermission,
	KindCanCreateLambdaEventSource,
	KindCanDeleteLambdaFunction,
	KindCanInvokeLambdaFunction,
	KindCanRemoveLambdaPermission,
	KindCanUpdateLambdaCode,
	KindCanUpdateLambdaConfiguration,
	KindCanUpdateLambdaURLConfig,
	KindCanCreateLambdaFunction,
	KindLambdaFunctionWrite,
	KindLambdaFunctionAll,
	KindCanModifyEC2InstanceAttribute,
	KindCanAssociateIAMInstanceProfile,
	KindCanReplaceIAMInstanceProfileAssociation,
	KindCanGetPasswordData,
	KindEC2CanVolumeSwap,
	KindCanDisassociateIAMInstanceProfile,
	KindCanTerminateInstances,
	KindCanCreateSnapshot,
	KindCanCreateImage,
	KindCanRunInstances,
	KindCanRequestSpotInstances,
	KindSSMCanSendCommand,
	KindSSMCanStartSession,
	KindCanCreateCloudFormationStack,
	KindCanCreateCloudFormationStackSet,
	KindCanUpdateCloudFormationStackSet,
	KindCanUpdateCloudFormationStack,
	KindCanExecuteCloudFormationChangeSet,
	KindClusterHasNodeGroup,
	KindNodeGroupHasRole,
	KindCanAssumeRoleViaIRSA,
	KindCanAssumeRoleViaPodIdentity,
	KindCanCreateAndAssociateEKSAccessEntry,
	KindCanCreateEKSNodegroup,
	KindCanCreateEKSPodIdentityAssociation,
}
