package store

import "testing"

// ResourceType derives the AWS resource type from an ARN by pure structural
// parsing — no external data (§7 of docs/authorization-tensor.md).
func TestResourceType(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::123456789012:role/Foo":                        "role",
		"arn:aws:iam::123456789012:user/alice":                      "user",
		"arn:aws:iam::123456789012:group/admins":                    "group",
		"arn:aws:iam::123456789012:policy/MyPolicy":                 "policy",
		"arn:aws:iam::aws:policy/AdministratorAccess":               "policy",
		"arn:aws:iam::123456789012:root":                            "account",
		"arn:aws:iam::123456789012:saml-provider/Corp":              "saml-provider",
		"arn:aws:iam::123456789012:oidc-provider/host.com":          "oidc-provider",
		"arn:aws:s3:::mybucket":                                     "bucket",
		"arn:aws:s3:::mybucket/some/key.txt":                        "object",
		"arn:aws:kms:us-east-1:123456789012:key/abcd-1234":          "key",
		"arn:aws:ssm:us-east-1:123456789012:parameter/foo":          "parameter",
		"arn:aws:lambda:us-east-1:123456789012:function:fn":         "function",
		"arn:aws:ec2:us-east-1:123456789012:instance/i-abc":         "instance",
		"arn:aws:cloudformation:us-east-1:123456789012:stack/nm/id": "stack",
		"not-an-arn":  "",
		"arn:aws:s3:": "",
	}
	for arn, want := range cases {
		if got := ResourceType(arn); got != want {
			t.Errorf("ResourceType(%q) = %q, want %q", arn, got, want)
		}
	}
}
