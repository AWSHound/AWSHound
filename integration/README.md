# AWS integration tests

The `Integration tests` GitHub Actions workflow runs on every push to `main` and
can also be started manually. It assumes short-lived credentials through GitHub
OIDC for the two dedicated AWS accounts, deploys and seeds real resources, runs
awshound's live collection and graph pipeline, and validates the resulting
nodes and edges.

The harness is self-contained in this repository. [`secondary.yaml`](secondary.yaml),
[`primary.yaml`](primary.yaml), and [`services.yaml`](services.yaml) create two IAM
negative controls, uncredentialed edge-test principals, IAM
users/groups/roles/policies, a SAML provider, a cross-account principal and trusted
role, S3, KMS, Lambda, SSM, EC2, and EKS resources. It reuses the account's GitHub
OIDC provider, which is already required for workflow authentication. Broad IAM
declarations exist only as graph inputs; the workflow does not exercise them and the
principals receive no access keys or login profiles. awshound collects every supported
non-Organizations service from both accounts and emits the OpenGraph.
[`validate.py`](validate.py) then checks 154 of 156 edge kinds, including:

- the deployed resources and CloudFormation stacks became graph nodes;
- structural containment, membership, policy attachment, and trust relationships;
- all IAM re-permission and credential-manipulation edges and their composites;
- the direct, cross-account, SAML/OIDC, and PassRole role-assumption paths;
- positive and negative same-account direct-principal role-trust controls,
  including identity- and trust-policy explicit Deny controls, boundary-allow
  and boundary-deny controls, and an account-root delegation control;
- positive and negative cross-account `aws:PrincipalTag` role-trust controls
  using only persistent IAM role tags;
- every S3 primitive and Read/Write/All meta edge, including suppression;
- all Lambda and CloudFormation authorization edges;
- all KMS, EC2, SSM, and EKS edge kinds, including a complete cluster with the
  Pod Identity Agent and callers that independently omit PassRole or Kubernetes
  cluster control; and
- forbidden edges for principals deliberately given no access.

Only `AWS_HasSCP` and `AWS_HasRCP` remain; they require an Organizations fixture.

Manual runs can select `all`, `iam`, `s3`, `cloudformation`, `lambda`, `ssm`,
`kms`, `ec2`, or `eks`. Each targeted suite collects IAM plus only the selected
service's required collectors. The KMS, EC2/SSM, and EKS conditions in
[`services.yaml`](services.yaml) ensure a targeted run deploys only that billable
service family. The workflow summary starts with any failed tests, followed by a
per-service PASS/FAIL table, the complete assertion table, and the asserted-edge
table. For example:

```sh
gh workflow run integration.yml --ref feat/expanded-integration-tests \
  -f operation=run -f suite=eks -f automatic_cleanup=true
```

Cleanup runs after success or failure with refreshed OIDC sessions. It deletes the
EKS control plane and node group, terminates all tagged EC2 instances, removes the
tagged EBS volumes and stacks, and verifies that the KMS key reached AWS's terminal
`PendingDeletion` state. AWS enforces a seven-day KMS deletion window; the alias is
removed immediately and AWS does not charge key-storage fees during that window.
The workflow check and GitHub run summary are the authoritative latest result.
Collected graphs, built artifacts, metrics, and raw logs remain only on the
ephemeral runner and are not uploaded as workflow artifacts.
For hands-on inspection, a manual run can set `automatic_cleanup=false`. This is
never honored for pushes to `main`. Afterwards, dispatch `operation=cleanup-only`
to remove every integration stack and directly verify that paid resources are
gone:

```sh
gh workflow run integration.yml --ref feat/expanded-integration-tests \
  -f operation=cleanup-only
```
