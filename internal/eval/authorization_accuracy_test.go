package eval_test

import (
	"testing"

	"github.com/AWSHound/AWSHound/internal/eval"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

const otherAcct = "444455556666"

func orgPolicy(arn, content string, accountIDs ...string) model.OrgPolicy {
	return model.OrgPolicy{Arn: arn, Content: content, AccountIds: accountIDs, Targets: []model.OrgPolicyTarget{{TargetId: accountIDs[0], Type: "ACCOUNT"}}}
}

func TestResourceAccountRCPPositiveAndNegative(t *testing.T) {
	principal := "arn:aws:iam::" + testAcct + ":user/cross"
	target := "arn:aws:lambda:us-east-1:" + otherAcct + ":function:target"
	identity := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}`
	allow := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}`
	deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:GetFunction","Resource":"*"}]}`

	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(principal, "cross", identity))
	s.AddAuthDetails(otherAcct, &model.AuthDetails{})
	store.IngestOrganizations(s, testAcct, &model.OrganizationsData{
		Organization: model.Organization{Id: "o-test", Arn: "arn:aws:organizations::" + testAcct + ":organization/o-test"},
		RCPPolicies: []model.OrgPolicy{
			orgPolicy("arn:aws:organizations::aws:policy/o-test/resource_control_policy/target", deny, otherAcct),
			orgPolicy("arn:aws:organizations::aws:policy/o-test/resource_control_policy/source", allow, testAcct),
		},
		AccountOrgPaths: map[string]string{},
	})
	pe, _ := eval.NewPolicyEvaluator(s)
	if result := pe.CanPerformAction(principal, "lambda:InvokeFunction", target, nil); result.Allowed || result.Outcome != eval.OutcomeDeniedByRCP {
		t.Fatalf("target-account RCP negative control = %+v", result)
	}

	s2 := store.New()
	s2.AddAuthDetails(testAcct, userWithInlinePolicy(principal, "cross", identity))
	s2.AddAuthDetails(otherAcct, &model.AuthDetails{})
	store.IngestOrganizations(s2, testAcct, &model.OrganizationsData{
		Organization: model.Organization{Id: "o-test", Arn: "arn:aws:organizations::" + testAcct + ":organization/o-test"},
		RCPPolicies: []model.OrgPolicy{
			orgPolicy("arn:aws:organizations::aws:policy/o-test/resource_control_policy/target", allow, otherAcct),
			orgPolicy("arn:aws:organizations::aws:policy/o-test/resource_control_policy/source", deny, testAcct),
		},
		AccountOrgPaths: map[string]string{},
	})
	pe2, _ := eval.NewPolicyEvaluator(s2)
	if result := pe2.CanPerformAction(principal, "lambda:InvokeFunction", target, nil); !result.Allowed {
		t.Fatalf("source-account RCP must not constrain target positive control = %+v", result)
	}
}

func TestOrganizationManagementAndServiceLinkedExemptions(t *testing.T) {
	managementUser := "arn:aws:iam::" + testAcct + ":user/management"
	serviceRole := "arn:aws:iam::" + otherAcct + ":role/aws-service-role/eks.amazonaws.com/managed"
	action := "ec2:DescribeInstances"
	identity := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"*"}]}`
	block := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(managementUser, "management", identity))
	s.AddAuthDetails(otherAcct, &model.AuthDetails{RoleDetailList: []model.RoleDetail{{Arn: serviceRole, RoleName: "managed", RolePolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: identity}}}}})
	store.IngestOrganizations(s, testAcct, &model.OrganizationsData{
		Organization:    model.Organization{Id: "o-test", Arn: "arn:aws:organizations::" + testAcct + ":organization/o-test", MasterAccountId: testAcct},
		SCPPolicies:     []model.OrgPolicy{orgPolicy("arn:aws:organizations::aws:policy/o-test/service_control_policy/block", block, testAcct, otherAcct)},
		AccountOrgPaths: map[string]string{},
	})
	pe, _ := eval.NewPolicyEvaluator(s)
	if result := pe.CanPerformAction(managementUser, action, "*", nil); !result.Allowed {
		t.Fatalf("management-account positive control = %+v", result)
	}
	if result := pe.CanPerformAction(serviceRole, action, "*", nil); !result.Allowed {
		t.Fatalf("service-linked-role positive control = %+v", result)
	}
}

func TestConditionalUniversalGuardrailAndIndependentConditions(t *testing.T) {
	principal := "arn:aws:iam::" + testAcct + ":user/conditional"
	action := "ec2:DescribeInstances"
	identity := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`
	scp := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-west-2"}}}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(principal, "conditional", identity))
	store.IngestOrganizations(s, testAcct, &model.OrganizationsData{
		Organization:    model.Organization{Id: "o-test", Arn: "arn:aws:organizations::" + testAcct + ":organization/o-test"},
		SCPPolicies:     []model.OrgPolicy{orgPolicy("arn:aws:organizations::aws:policy/o-test/service_control_policy/conditional", scp, testAcct)},
		AccountOrgPaths: map[string]string{},
	})
	pe, _ := eval.NewPolicyEvaluator(s)
	if result := pe.CanPerformAction(principal, action, "arn:aws:ec2:us-east-1:"+testAcct+":instance/i-east", nil); result.Allowed {
		t.Fatalf("contradictory condition negative control = %+v", result)
	}
	if result := pe.CanPerformAction(principal, action, "arn:aws:ec2:us-west-2:"+testAcct+":instance/i-west", nil); result.Allowed {
		t.Fatalf("conditional universal SCP must not become baseline = %+v", result)
	}
}

func TestFutureResourcePatternPositiveAndNegative(t *testing.T) {
	principal := "arn:aws:iam::" + testAcct + ":user/lambda-builder"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:us-east-1:` + testAcct + `:function:goawshound-*"}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(principal, "lambda-builder", doc))
	pe, _ := eval.NewPolicyEvaluator(s)
	if result := pe.CanPerformActionPattern(principal, "lambda:CreateFunction", "arn:aws:lambda:us-east-1:"+testAcct+":function:*", nil); !result.Allowed {
		t.Fatalf("future Lambda ARN positive control = %+v", result)
	}
	if result := pe.CanPerformActionPattern(principal, "lambda:CreateFunction", "arn:aws:lambda:us-west-2:"+testAcct+":function:*", nil); result.Allowed {
		t.Fatalf("future Lambda region negative control = %+v", result)
	}
}

func TestEC2ResourceTagAndManagedOperatorContext(t *testing.T) {
	principal := "arn:aws:iam::" + testAcct + ":user/ec2-operator"
	tagAction := "ec2:ModifyInstanceAttribute"
	managedAction := "ec2:TerminateInstances"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + tagAction + `","Resource":"*","Condition":{"StringEquals":{"ec2:ResourceTag/environment":"prod"}}},{"Effect":"Allow","Action":"` + managedAction + `","Resource":"*","Condition":{"StringEquals":{"ec2:ManagedResourceOperator":"eks.amazonaws.com"}}}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, userWithInlinePolicy(principal, "ec2-operator", doc))
	store.IngestEKS(s, testAcct, &model.EKSData{NodeGroups: []model.EKSNodeGroup{{
		NodegroupArn: "arn:aws:eks:us-east-1:" + testAcct + ":nodegroup/cluster/workers/id", ClusterName: "cluster", NodegroupName: "workers", Resources: &model.EKSNodeGroupResources{AutoScalingGroups: []model.EKSAutoScalingGroup{{Name: "eks-asg"}}},
	}}})
	store.IngestEC2(s, testAcct, &model.EC2Data{Instances: []model.EC2Instance{
		{InstanceId: "i-managed", Region: "us-east-1", Tags: []model.Tag{{Key: "environment", Value: "prod"}, {Key: "aws:autoscaling:groupName", Value: "eks-asg"}}},
		{InstanceId: "i-standalone", Region: "us-east-1", Tags: []model.Tag{{Key: "environment", Value: "dev"}}},
	}})
	pe, _ := eval.NewPolicyEvaluator(s)
	managed := "arn:aws:ec2:us-east-1:" + testAcct + ":instance/i-managed"
	standalone := "arn:aws:ec2:us-east-1:" + testAcct + ":instance/i-standalone"
	if result := pe.CanPerformAction(principal, tagAction, managed, nil); !result.Allowed {
		t.Fatalf("EC2 tag positive control = %+v", result)
	}
	if result := pe.CanPerformAction(principal, tagAction, standalone, nil); result.Allowed {
		t.Fatalf("EC2 tag negative control = %+v", result)
	}
	if result := pe.CanPerformAction(principal, managedAction, managed, nil); !result.Allowed {
		t.Fatalf("managed-resource positive control = %+v", result)
	}
	if result := pe.CanPerformAction(principal, managedAction, standalone, nil); result.Allowed {
		t.Fatalf("managed-resource negative control = %+v", result)
	}
}

func TestNotResourceConjunctionRemainsExact(t *testing.T) {
	principal := "arn:aws:iam::" + testAcct + ":user/not-resource"
	action := "s3:GetObject"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action + `","NotResource":"arn:aws:s3:::private/*"}]}`
	boundaryArn := "arn:aws:iam::" + testAcct + ":policy/boundary"
	boundary := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","NotResource":"arn:aws:s3:::sensitive/*"}]}`
	s := store.New()
	s.AddAuthDetails(testAcct, &model.AuthDetails{
		UserDetailList: []model.UserDetail{{Arn: principal, UserName: "not-resource", UserPolicyList: []model.InlinePolicy{{PolicyName: "p", PolicyDocument: doc}}, PermissionsBoundary: &model.PermBoundary{PermissionsBoundaryArn: boundaryArn}}},
		Policies:       []model.PolicyDetail{{Arn: boundaryArn, PolicyName: "boundary", DefaultVersionId: "v1", PolicyVersions: []model.PolicyVersion{{VersionId: "v1", Document: boundary, IsDefaultVersion: true}}}},
	})
	pe, _ := eval.NewPolicyEvaluator(s)
	if result := pe.CanPerformAction(principal, action, "arn:aws:s3:::public/file", nil); !result.Allowed {
		t.Fatalf("NotResource positive control = %+v", result)
	}
	if result := pe.CanPerformAction(principal, action, "arn:aws:s3:::private/file", nil); result.Allowed {
		t.Fatalf("identity NotResource negative control = %+v", result)
	}
	if result := pe.CanPerformAction(principal, action, "arn:aws:s3:::sensitive/file", nil); result.Allowed {
		t.Fatalf("boundary NotResource negative control = %+v", result)
	}
}
