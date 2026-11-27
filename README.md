# awshound

[![Integration tests](https://github.com/AWSHound/AWSHound/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/AWSHound/AWSHound/actions/workflows/integration.yml)

<p align="center">
  <img src="assets/awshound-logo.png" alt="AWSHound logo" width="720">
</p>

awshound collects AWS IAM/authorization data and builds a
[BloodHound](https://github.com/SpecterOps/BloodHound) OpenGraph. 

See the [AWSHound wiki](https://github.com/AWSHound/AWSHound/wiki) for project
documentation.

## Pipeline

Collection runs in three phases, exposed both as standalone subcommands (with
on-disk artifacts between them) and as a single `all` run:

| Command   | Input → output                        | What it does                                  |
|-----------|---------------------------------------|-----------------------------------------------|
| `collect` | AWS → `raw/`                          | fetch AWS data into a directory of raw JSON   |
| `process` | `raw/` → `built.json`                 | build the graph (raw ARN ids)                 |
| `emit`    | `built.json` → `graph.json`           | encode the built graph as OpenGraph JSON      |
| `all`     | AWS \| `raw/` \| GAAD → `graph.json`  | run every phase in one invocation             |

Run `awshound <command> -h` for a command's full flag list.

## Build

```sh
go build -o awshound ./cmd/awshound
```

Or use the published container image, whose entrypoint is the binary:

```sh
docker run --rm ghcr.io/awshound/awshound:latest all --help
```

## Authentication & account selection

Live collection (the `collect` and `all` subcommands) authenticates with AWS and
chooses which accounts to collect from **one or more** of the following sources.
At least one is required.

### `--profile NAME`

Collect one or more named AWS CLI profiles directly. Repeatable and/or
comma-separated:

```sh
awshound all --profile prod -o graph.json
awshound all --profile prod --profile staging -o graph.json
awshound all --profile prod,staging -o graph.json
```

Credentials resolve through the normal AWS chain for that profile (shared config
and credentials files, SSO, assumed roles). Explicit `--profile` names are merged
(de-duplicated) with any profiles discovered via `--aws-config`.

### `--aws-config FILE`

Collect every profile in an AWS config file whose section opts in with
`bloodhound_collect = true`. This lets you keep the collection set in the config
file itself instead of listing `--profile` flags:

```ini
# ~/.aws/config
[profile prod]
region = us-east-1
bloodhound_collect = true

[profile staging]
bloodhound_collect = true

[profile scratch]
# not collected — no opt-in marker
```

```sh
awshound all --aws-config ~/.aws/config -o graph.json
```

Use `--aws-credentials FILE` to point at a shared credentials file other than
`~/.aws/credentials`.

### `--org-role ROLE`

Assume `ROLE` across an entire AWS Organization and collect every account in one
run:

```sh
awshound all --org-role OrganizationAccountAccessRole -o graph.json
```

The base identity — the first `--profile` if given, otherwise the ambient/default
credential chain (honoring `--aws-config` / `--aws-credentials`) — must be able to
enumerate the organization. awshound then:

1. discovers the active organization accounts (`sts:GetCallerIdentity` +
   `organizations:ListAccounts`);
2. collects the **management account** directly;
3. assumes `arn:aws:iam::<account-id>:role/ROLE` into each **child account** and
   collects it.

`ROLE` is required and has no implicit default — pass
`OrganizationAccountAccessRole` (the role AWS creates in member accounts) or your
own cross-account collection role, e.g. `--org-role=MyAuditRole`. A child account
whose role can't be assumed is logged and skipped, so the run still produces a
graph for the accounts that succeeded.

## Region scoping

By default each account's enabled regions are auto-discovered. Restrict the
region-scoped collectors with `--regions`:

```sh
awshound all --profile prod --regions us-east-1,us-west-2 -o graph.json
```

## Service selection & S3

By default awshound collects `iam`, `kms`, `ssm`, `ec2`, `lambda`,
`cloudformation`, `eks`, and `organizations`. `s3` is opt-in because per-bucket
control-plane and object-listing calls can dominate runtime on bucket-heavy
accounts.

`--collectors` replaces the default collector list rather than appending to it,
so pass the full service list (at minimum `iam,s3`) when including S3:

```sh
awshound all --profile prod \
  --collectors iam,kms,ssm,ec2,lambda,cloudformation,eks,organizations,s3 \
  -o graph.json
```

To bound S3 bucket/object graph volume during ingestion, pass `--s3-filter`
with a filter config (for example [`configs/s3-filter.bucket-only.json`](configs/s3-filter.bucket-only.json)
to retain all buckets while excluding objects, or [`configs/s3-filter.bounded.json`](configs/s3-filter.bounded.json)
to cap objects per bucket; note that [`configs/s3-filter.default.json`](configs/s3-filter.default.json)
sets `"default": "exclude"` without `"include"` rules and excludes all buckets
unless customized).

## AWS API request metrics and budgets

Pass `--metrics <path>` to a live `collect` or `all` run to record request-level
AWS activity in the report's `awsApi` section. The terminal summary and JSON
break it down by AWS service and operation. They include logical SDK calls,
HTTP attempts sent, retries, successful/failed calls, throttles, API and
transport errors, time spent waiting for the request limiter, and aggregate/max
HTTP transport latency (through receipt of the response headers).

An attempt is one AWS SDK HTTP send admitted to the transport. Paginator pages,
SDK retries, redirects, calls made while bootstrapping credentials/accounts,
and calls across every selected account and Region therefore count separately.
This is intentionally different from `collectUnits`, which measures collector
work items rather than API traffic. A local transport failure conservatively
consumes a budget slot even when AWS may not have processed the request.

Live collection also supports two run-wide safeguards:

```sh
awshound collect --profile prod --metrics metrics.json \
  --max-api-requests 20000 \
  --max-api-requests-per-minute 600
```

`--max-api-requests` stops with a non-zero status before admitting an attempt
that would exceed the total. The metrics report is still written with
`awsApi.limitExceeded: true`; raw service files written before cancellation
remain usable with `--resume`, while an active account batch is not marked
complete.
`--max-api-requests-per-minute` instead waits as necessary so that no more than
the selected number of attempts start in any rolling 60-second window. Both
limits count retries and default to unlimited (`0`).

These limits govern this awshound process's aggregate traffic. AWS quotas can
be scoped by service, operation, account, and Region, and other workloads may
share them, so select a conservative value appropriate to the authorized
environment. `--max-concurrency` is a separate collector-worker bound; it is not
an API request-rate limit.

## Offline builds

Build a graph from previously collected data without touching AWS:

```sh
awshound all --input-dir raw/ -o graph.json      # from a raw collect directory
awshound all --gaad auth-details.json -o graph.json  # from a single GAAD file
```
