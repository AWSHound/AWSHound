#!/usr/bin/env python3
"""Validate an AWS collector graph against the live fixture and BHE schema."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any
from zipfile import ZipFile

PRIMARY_ACCOUNT = os.environ.get("PRIMARY_ACCOUNT_ID", "")
SECONDARY_ACCOUNT = os.environ.get("SECONDARY_ACCOUNT_ID", "")
PRIMARY_STACK = "goawshound-integration-primary"
SECONDARY_STACK = "goawshound-integration-secondary"
BUCKET = f"goawshound-integration-{PRIMARY_ACCOUNT}-us-east-1"
READER_USER = "goawshound-integration-reader"
DENIED_USER = "goawshound-integration-denied"
EXTERNAL_USER = "goawshound-integration-external"
CROSS_ACCOUNT_ROLE = "goawshound-integration-cross-account"
PRINCIPAL_TAG_ALLOWED_ROLE = "goawshound-integration-principal-tag-allowed"
PRINCIPAL_TAG_DENIED_ROLE = "goawshound-integration-principal-tag-denied"
PRINCIPAL_TAG_TARGET_ROLE = "goawshound-integration-principal-tag-target"
DIRECT_TRUST_ALLOWED_USER = "goawshound-integration-direct-trust-allowed"
DIRECT_TRUST_DENIED_USER = "goawshound-integration-direct-trust-denied"
DIRECT_TRUST_BOUNDARY_ALLOWED_USER = (
    "goawshound-integration-direct-trust-boundary-allowed"
)
DIRECT_TRUST_BOUNDARY_DENIED_USER = (
    "goawshound-integration-direct-trust-boundary-denied"
)
DIRECT_TRUST_RESOURCE_DENIED_USER = (
    "goawshound-integration-direct-trust-resource-denied"
)
DIRECT_TRUST_TARGET_ROLE = "goawshound-integration-direct-trust-target"
ACCOUNT_DELEGATED_TRUST_TARGET_ROLE = (
    "goawshound-integration-account-delegated-trust-target"
)
EDGE_OPERATOR = "goawshound-integration-edge-operator"
TARGET_USER = "goawshound-integration-target"
TARGET_GROUP = "goawshound-integration-group"
TARGET_ROLE = "goawshound-integration-target"
MANAGED_POLICY = "goawshound-integration-managed-policy"
ROLE_MANAGED_POLICY = "goawshound-integration-role-managed-policy"
SAML_PROVIDER = "goawshound-integration-saml"
OIDC_PROVIDER_PATH = "token.actions.githubusercontent.com"
S3_ACL_READER = "goawshound-integration-s3-acl"
S3_BUCKET_ALL_USER = "goawshound-integration-s3-bucket-all"
S3_BUCKET_WRITE_USER = "goawshound-integration-s3-bucket-write"
S3_BUCKET_READ_USER = "goawshound-integration-s3-bucket-read"
S3_OBJECT_ALL_USER = "goawshound-integration-s3-object-all"
S3_OBJECT_WRITE_USER = "goawshound-integration-s3-object-write"
S3_OBJECT_READ_USER = "goawshound-integration-s3-object-read"
STACKSET = "goawshound-integration-stackset"
LAMBDA_FUNCTION = "goawshound-integration-function"
LAMBDA_PRIMITIVE_USER = "goawshound-integration-lambda-primitives"
LAMBDA_CONFIGURATION_USER = "goawshound-integration-lambda-configuration"
LAMBDA_WRITE_USER = "goawshound-integration-lambda-write"
KMS_PRIMITIVE_USER = "goawshound-integration-kms-primitives"
KMS_GENERATE_USER = "goawshound-integration-kms-generate"
KMS_READ_USER = "goawshound-integration-kms-read"
KMS_ALIAS = "alias/goawshound-integration"
EC2_INSTANCE = "goawshound-integration-instance"
COMPUTE_ROLE = "goawshound-integration-compute"
EKS_CLUSTER = "goawshound-integration"
EKS_NODEGROUP = "goawshound-integration"
EKS_IRSA_ROLE = "goawshound-integration-irsa"
EKS_POD_IDENTITY_ROLE = "goawshound-integration-pod-identity"
EKS_POD_IDENTITY_COMPLETE_USER = "goawshound-integration-pod-identity-complete"
EKS_POD_IDENTITY_NO_PASS_ROLE_USER = (
    "goawshound-integration-pod-identity-no-pass-role"
)
EKS_POD_IDENTITY_NO_CLUSTER_ACCESS_USER = (
    "goawshound-integration-pod-identity-no-cluster-access"
)
EKS_SERVICE_ROLE = "AWSServiceRoleForAmazonEKS"
OBJECT_KEY = "integration-fixture.txt"
ASSERTED_EDGE_KINDS = 154
KMS_KEY_CAPABILITY_EDGE_KINDS = (
    "AWS_CanCreateKMSGrant",
    "AWS_CanDecryptKMSKey",
    "AWS_CanDisableKMSKey",
    "AWS_CanEncryptKMSKey",
    "AWS_CanGenerateKMSDataKey",
    "AWS_CanModifyKMSKeyPolicy",
    "AWS_CanScheduleKMSKeyDeletion",
    "AWS_CanSelfGrantKMSOps",
    "AWS_KMSKeyAll",
    "AWS_KMSKeyRead",
)
SUITE_COLLECTORS = {
    "all": ("iam", "s3", "cloudformation", "lambda", "ssm", "kms", "ec2", "eks"),
    "iam": ("iam",),
    "s3": ("iam", "s3"),
    "cloudformation": ("iam", "cloudformation"),
    "lambda": ("iam", "lambda"),
    "ssm": ("iam", "ssm", "ec2"),
    "kms": ("iam", "kms"),
    "ec2": ("iam", "ec2"),
    "eks": ("iam", "eks"),
}


def encode_id(value: str) -> str:
    return value.replace(":", "_")


def load_json(path: Path) -> Any:
    if path.is_dir():
        documents = [load_json(item) for item in sorted(path.rglob("*.json"))]
        if not documents:
            raise ValueError(f"{path} contains no JSON files")
        source_kinds = {
            document.get("metadata", {}).get("source_kind") for document in documents
        }
        return {
            "metadata": {
                "source_kind": source_kinds.pop() if len(source_kinds) == 1 else None
            },
            "graph": {
                "nodes": [
                    node
                    for document in documents
                    for node in document.get("graph", document).get("nodes", [])
                ],
                "edges": [
                    edge
                    for document in documents
                    for edge in document.get("graph", document).get("edges", [])
                ],
            },
        }
    if path.suffix.lower() == ".zip":
        with ZipFile(path) as archive:
            members = sorted(
                (
                    info
                    for info in archive.infolist()
                    if not info.is_dir()
                    and Path(info.filename).suffix.lower() == ".json"
                ),
                key=lambda info: info.filename,
            )
            if not members:
                raise ValueError(f"{path} contains no JSON member")
            with archive.open(members[0]) as handle:
                return json.load(handle)
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class Report:
    def __init__(self, selected_suite: str, project: str) -> None:
        self.selected_suite = selected_suite
        self.project = project
        self.current_suite = "common"
        self.total = 0
        self.failed = 0
        self.results: list[tuple[str, str, bool]] = []

    def use_suite(self, suite: str) -> None:
        self.current_suite = suite

    def enabled(self) -> bool:
        return self.selected_suite == "all" or self.current_suite in {
            "common",
            self.selected_suite,
        }

    def check(self, description: str, condition: bool) -> None:
        if not self.enabled():
            return
        self.total += 1
        marker = "PASS" if condition else "FAIL"
        print(f"  [{marker}] {description}")
        self.results.append((self.current_suite, description, condition))
        if not condition:
            self.failed += 1

    def markdown(
        self,
        edge_counts: Counter[str],
        asserted_edge_kinds: set[str],
        edge_assertions: dict[str, list[bool]],
        total_edge_kinds: int,
    ) -> str:
        passed = self.total - self.failed
        lines = [
            f"## {self.project} live integration details ({self.selected_suite} suite)",
            "",
            (
                f"{passed}/{self.total} checks passed; "
                f"{len(asserted_edge_kinds)}/{total_edge_kinds} distinct edge kinds asserted."
            ),
        ]
        failed_tests = [
            (suite, description)
            for suite, description, condition in self.results
            if not condition
        ]
        if failed_tests:
            lines.extend(
                (
                    "",
                    "### Failed tests",
                    "",
                    "| Result | Service | Test |",
                    "| --- | --- | --- |",
                )
            )
            for suite, description in failed_tests:
                safe_description = description.replace("|", "\\|")
                lines.append(f"| FAIL | {suite} | {safe_description} |")

        service_totals = Counter(suite for suite, _, _ in self.results)
        service_passes = Counter(
            suite for suite, _, condition in self.results if condition
        )
        lines.extend(
            (
                "",
                "### Service status",
                "",
                "| Result | Service | Checks passed |",
                "| --- | --- | ---: |",
            )
        )
        for suite in sorted(service_totals):
            checks_passed = service_passes[suite]
            checks_total = service_totals[suite]
            result = "PASS" if checks_passed == checks_total else "FAIL"
            lines.append(f"| {result} | {suite} | {checks_passed}/{checks_total} |")

        lines.extend(
            (
                "",
                "### Test results",
                "",
                "| Result | Service | Test |",
                "| --- | --- | --- |",
            )
        )
        for suite, description, condition in self.results:
            safe_description = description.replace("|", "\\|")
            lines.append(
                f"| {'PASS' if condition else 'FAIL'} | {suite} | {safe_description} |"
            )
        lines.extend(
            (
                "",
                "### Asserted edges",
                "",
                "| Result | Edge kind | Exact assertions passed | Edges observed in graph |",
                "| --- | --- | ---: | ---: |",
            )
        )
        for kind in sorted(asserted_edge_kinds):
            assertions = edge_assertions[kind]
            assertion_passes = sum(assertions)
            result = "PASS" if assertion_passes == len(assertions) else "FAIL"
            lines.append(
                f"| {result} | {kind} | {assertion_passes}/{len(assertions)} | "
                f"{edge_counts[kind]} |"
            )
        lines.append("")
        return "\n".join(lines)

    def finish(self) -> int:
        passed = self.total - self.failed
        print(f"TOTAL: {passed}/{self.total} checks passed")
        if self.failed:
            print(f"RESULT: {self.failed} FAILURE(S)")
            return 1
        print("RESULT: ALL PASSED")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("graph", type=Path)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--error-log", type=Path)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--project", default="AWS collector")
    parser.add_argument(
        "--raw-layout", choices=("goawshound", "openhound"), default="goawshound"
    )
    parser.add_argument("--summary", type=Path)
    parser.add_argument(
        "--suite", choices=tuple(SUITE_COLLECTORS), default="all", help="test suite"
    )
    args = parser.parse_args()

    if not PRIMARY_ACCOUNT or not SECONDARY_ACCOUNT:
        parser.error(
            "PRIMARY_ACCOUNT_ID and SECONDARY_ACCOUNT_ID must be provided in the environment"
        )

    document = load_json(args.graph)
    graph = document.get("graph", document)
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    nodes_by_id = {node["id"]: node for node in nodes}
    schema = load_json(args.schema)
    schema_node_kinds = {item["name"] for item in schema.get("node_kinds", [])}
    schema_edge_kinds = {
        item["name"] for item in schema.get("relationship_kinds", [])
    }

    def endpoint_ids(endpoint: dict[str, Any]) -> set[str]:
        if endpoint.get("match_by") != "property":
            value = endpoint.get("value")
            return {str(value)} if value is not None else set()
        kind = endpoint.get("kind")
        matchers = endpoint.get("property_matchers", [])
        return {
            item["id"]
            for item in nodes
            if kind in item.get("kinds", [])
            and all(
                matcher.get("operator", "equals") == "equals"
                and item.get("properties", {}).get(matcher.get("key"))
                == matcher.get("value")
                for matcher in matchers
            )
        }

    edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in edges:
        for start_id in endpoint_ids(item.get("start", {})):
            for end_id in endpoint_ids(item.get("end", {})):
                edges_by_key[(start_id, end_id, item.get("kind", ""))] = item

    report = Report(args.suite, args.project)
    required_edge_kinds: set[str] = set()
    edge_assertions: dict[str, list[bool]] = {}

    def record_edge_assertion(kind: str, condition: bool) -> None:
        if not report.enabled():
            return
        required_edge_kinds.add(kind)
        edge_assertions.setdefault(kind, []).append(condition)

    def node_ids(value: str) -> set[str]:
        candidates = {value, encode_id(value)}
        for item in nodes:
            properties = item.get("properties", {})
            if properties.get("arn") == value:
                candidates.add(item["id"])
            if value.startswith("arn:aws:iam::") and value.endswith(":root"):
                account_id = value.split(":")[4]
                if (
                    "AWS_Account" in item.get("kinds", [])
                    and properties.get("account_id") == account_id
                ):
                    candidates.add(item["id"])
        return candidates

    def node(arn: str, kind: str) -> bool:
        return any(kind in nodes_by_id.get(item_id, {}).get("kinds", []) for item_id in node_ids(arn))

    def edge(start: str, end: str, kind: str) -> bool:
        found = any(
            (start_id, end_id, kind) in edges_by_key
            for start_id in node_ids(start)
            for end_id in node_ids(end)
        )
        record_edge_assertion(kind, found)
        return found

    def absent_edge(start: str, end: str, kind: str) -> bool:
        missing = all(
            (start_id, end_id, kind) not in edges_by_key
            for start_id in node_ids(start)
            for end_id in node_ids(end)
        )
        record_edge_assertion(kind, missing)
        return missing

    def edge_record(start: str, end: str, kind: str) -> dict[str, Any]:
        item = next(
            (
                edges_by_key[(start_id, end_id, kind)]
                for start_id in node_ids(start)
                for end_id in node_ids(end)
                if (start_id, end_id, kind) in edges_by_key
            ),
            {},
        )
        record_edge_assertion(kind, bool(item))
        return item

    def node_id_by_fixture(
        kind: str,
        account_id: str,
        names: tuple[str, ...] = (),
        arn_fragments: tuple[str, ...] = (),
        required_properties: dict[str, Any] | None = None,
    ) -> str:
        required_properties = required_properties or {}
        return next(
            (
                item["id"]
                for item in nodes
                if kind in item.get("kinds", [])
                and item.get("properties", {}).get("account_id") == account_id
                and all(
                    item.get("properties", {}).get(key) == value
                    for key, value in required_properties.items()
                )
                and (
                    (not names and not arn_fragments)
                    or any(
                        item.get("properties", {}).get(key)
                        in {name, f"{account_id}:{name}"}
                        for key in ("name", "displayname")
                        for name in names
                    )
                    or any(
                        fragment in item.get("properties", {}).get("arn", "")
                        for fragment in arn_fragments
                    )
                )
            ),
            "",
        )

    def fixture_stack_id(account_id: str, name: str) -> str:
        return node_id_by_fixture(
            "AWS_CloudFormationStack",
            account_id,
            names=(name,),
            arn_fragments=(f":stack/{name}/",),
        )

    def fixture_stackset_id(account_id: str, name: str) -> str:
        return node_id_by_fixture(
            "AWS_CloudFormationStackSet",
            account_id,
            names=(name,),
            arn_fragments=(f":stackset/{name}:",),
        )

    def check_no_edges_to_nodes(
        description: str, target_ids: set[str], kinds: tuple[str, ...]
    ) -> None:
        for kind in kinds:
            offenders = [
                item
                for item in edges
                if item.get("kind") == kind
                and endpoint_ids(item.get("end", {})) & target_ids
            ]
            report.check(f"{description}: {kind}", not offenders)
            if report.enabled() and offenders:
                print(f"    {len(offenders)} offending edge(s)")

    def check_edges(
        description: str, start: str, end: str, kinds: tuple[str, ...]
    ) -> None:
        for kind in kinds:
            report.check(f"{description}: {kind}", edge(start, end, kind))

    primary_root = f"arn:aws:iam::{PRIMARY_ACCOUNT}:root"
    secondary_root = f"arn:aws:iam::{SECONDARY_ACCOUNT}:root"
    reader = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{READER_USER}"
    primary_denied = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{DENIED_USER}"
    external = f"arn:aws:iam::{SECONDARY_ACCOUNT}:user/{EXTERNAL_USER}"
    secondary_denied = f"arn:aws:iam::{SECONDARY_ACCOUNT}:user/{DENIED_USER}"
    role = f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{CROSS_ACCOUNT_ROLE}"
    principal_tag_allowed = (
        f"arn:aws:iam::{SECONDARY_ACCOUNT}:role/{PRINCIPAL_TAG_ALLOWED_ROLE}"
    )
    principal_tag_denied = (
        f"arn:aws:iam::{SECONDARY_ACCOUNT}:role/{PRINCIPAL_TAG_DENIED_ROLE}"
    )
    principal_tag_target = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{PRINCIPAL_TAG_TARGET_ROLE}"
    )
    direct_trust_allowed = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{DIRECT_TRUST_ALLOWED_USER}"
    )
    direct_trust_denied = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{DIRECT_TRUST_DENIED_USER}"
    )
    direct_trust_boundary_allowed = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{DIRECT_TRUST_BOUNDARY_ALLOWED_USER}"
    )
    direct_trust_boundary_denied = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{DIRECT_TRUST_BOUNDARY_DENIED_USER}"
    )
    direct_trust_resource_denied = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{DIRECT_TRUST_RESOURCE_DENIED_USER}"
    )
    direct_trust_target = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{DIRECT_TRUST_TARGET_ROLE}"
    )
    account_delegated_trust_target = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{ACCOUNT_DELEGATED_TRUST_TARGET_ROLE}"
    )
    operator = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{EDGE_OPERATOR}"
    target_user = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{TARGET_USER}"
    target_group = f"arn:aws:iam::{PRIMARY_ACCOUNT}:group/{TARGET_GROUP}"
    target_role = f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{TARGET_ROLE}"
    managed_policy = f"arn:aws:iam::{PRIMARY_ACCOUNT}:policy/{MANAGED_POLICY}"
    role_managed_policy = f"arn:aws:iam::{PRIMARY_ACCOUNT}:policy/{ROLE_MANAGED_POLICY}"
    saml_provider = f"arn:aws:iam::{PRIMARY_ACCOUNT}:saml-provider/{SAML_PROVIDER}"
    oidc_provider = f"arn:aws:iam::{PRIMARY_ACCOUNT}:oidc-provider/{OIDC_PROVIDER_PATH}"
    s3_acl_reader = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_ACL_READER}"
    s3_bucket_all = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_BUCKET_ALL_USER}"
    s3_bucket_write = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_BUCKET_WRITE_USER}"
    s3_bucket_read = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_BUCKET_READ_USER}"
    s3_object_all = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_OBJECT_ALL_USER}"
    s3_object_write = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_OBJECT_WRITE_USER}"
    s3_object_read = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{S3_OBJECT_READ_USER}"
    lambda_primitive_user = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{LAMBDA_PRIMITIVE_USER}"
    )
    lambda_configuration_user = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{LAMBDA_CONFIGURATION_USER}"
    )
    lambda_write_user = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{LAMBDA_WRITE_USER}"
    lambda_function = (
        f"arn:aws:lambda:us-east-1:{PRIMARY_ACCOUNT}:function:{LAMBDA_FUNCTION}"
    )
    ssm_parameter = f"arn:aws:ssm:us-east-1:{PRIMARY_ACCOUNT}:parameter/goawshound/integration/parameter"
    kms_primitive_user = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{KMS_PRIMITIVE_USER}"
    kms_generate_user = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{KMS_GENERATE_USER}"
    kms_read_user = f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{KMS_READ_USER}"
    compute_role = f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{COMPUTE_ROLE}"
    eks_cluster = f"arn:aws:eks:us-east-1:{PRIMARY_ACCOUNT}:cluster/{EKS_CLUSTER}"
    eks_irsa_role = f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{EKS_IRSA_ROLE}"
    eks_pod_identity_role = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/{EKS_POD_IDENTITY_ROLE}"
    )
    eks_pod_identity_complete = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{EKS_POD_IDENTITY_COMPLETE_USER}"
    )
    eks_pod_identity_no_pass_role = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{EKS_POD_IDENTITY_NO_PASS_ROLE_USER}"
    )
    eks_pod_identity_no_cluster_access = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:user/{EKS_POD_IDENTITY_NO_CLUSTER_ACCESS_USER}"
    )
    eks_service_role = (
        f"arn:aws:iam::{PRIMARY_ACCOUNT}:role/aws-service-role/"
        f"eks.amazonaws.com/{EKS_SERVICE_ROLE}"
    )
    bucket = f"arn:aws:s3:::{BUCKET}"
    fixture_object = f"{bucket}/{OBJECT_KEY}"

    print("Graph document")
    schema_info = schema.get("schema", {})
    report.check("BHE schema declares AWS namespace", schema_info.get("namespace") == "AWS")
    report.check("BHE schema declares node kinds", bool(schema_node_kinds))
    report.check("BHE schema declares relationship kinds", bool(schema_edge_kinds))
    report.check(
        "metadata identifies an AWS OpenGraph",
        document.get("metadata", {}).get("source_kind") == "AWS",
    )
    report.check("graph contains nodes", bool(nodes))
    report.check("graph contains edges", bool(edges))
    observed_node_kinds = {
        kind
        for item in nodes
        for kind in item.get("kinds", [])
        if kind.startswith("AWS_")
    }
    observed_edge_kinds = {item.get("kind") for item in edges}
    unknown_node_kinds = observed_node_kinds - schema_node_kinds
    unknown_edge_kinds = observed_edge_kinds - schema_edge_kinds
    report.check(
        "every emitted AWS node kind is in the BHE schema",
        not unknown_node_kinds,
    )
    if unknown_node_kinds:
        print(f"  unknown node kinds: {', '.join(sorted(unknown_node_kinds))}")
    report.check(
        "every emitted relationship kind is in the BHE schema",
        not unknown_edge_kinds,
    )
    if unknown_edge_kinds:
        print(f"  unknown relationship kinds: {', '.join(sorted(unknown_edge_kinds))}")
    report.check(
        "every graph node has the OpenGraph fields required by the schema contract",
        all(
            isinstance(item.get("id"), str)
            and bool(item.get("id"))
            and isinstance(item.get("kinds"), list)
            and isinstance(item.get("properties"), dict)
            for item in nodes
        ),
    )
    print("Collected artifacts")
    if args.raw_layout == "goawshound":
        for account_label, account in (
            ("primary", PRIMARY_ACCOUNT),
            ("secondary", SECONDARY_ACCOUNT),
        ):
            for service in SUITE_COLLECTORS[args.suite]:
                raw_file = args.raw / account / f"{service}.json"
                report.check(
                    f"collected {account_label}/{service}.json",
                    raw_file.is_file() and raw_file.stat().st_size > 0,
                )
    else:
        for account_name in ("primary", "secondary"):
            report.check(
                f"collected {account_name} OpenHound resources",
                any((args.raw / account_name / "aws").rglob("*.jsonl.gz")),
            )
    if args.error_log is not None and args.error_log.exists():
        error_report = load_json(args.error_log)
        report.check(
            "collector reported no service-level errors",
            error_report.get("total", 0) == 0,
        )

    print("Fixture nodes")
    report.use_suite("iam")
    for arn, kind, description in (
        (primary_root, "AWS_Account", "primary AWS account"),
        (secondary_root, "AWS_Account", "secondary AWS account"),
        (reader, "AWS_User", "primary reader user"),
        (primary_denied, "AWS_User", "primary negative-control user"),
        (external, "AWS_User", "secondary cross-account user"),
        (secondary_denied, "AWS_User", "secondary negative-control user"),
        (role, "AWS_Role", "cross-account role"),
        (principal_tag_allowed, "AWS_Role", "persistently tagged caller role"),
        (principal_tag_denied, "AWS_Role", "untagged caller role"),
        (principal_tag_target, "AWS_Role", "principal-tag trust target role"),
        (direct_trust_allowed, "AWS_User", "direct-trust positive user"),
        (direct_trust_denied, "AWS_User", "direct-trust explicit-deny user"),
        (
            direct_trust_boundary_allowed,
            "AWS_User",
            "direct-trust boundary-allowed user",
        ),
        (
            direct_trust_boundary_denied,
            "AWS_User",
            "direct-trust boundary-negative user",
        ),
        (
            direct_trust_resource_denied,
            "AWS_User",
            "direct-trust trust-policy-denied user",
        ),
        (direct_trust_target, "AWS_Role", "direct-trust target role"),
        (
            account_delegated_trust_target,
            "AWS_Role",
            "account-delegated trust target role",
        ),
        (operator, "AWS_User", "edge operator user"),
        (target_user, "AWS_User", "IAM target user"),
        (target_group, "AWS_Group", "IAM target group"),
        (target_role, "AWS_Role", "IAM target role"),
        (managed_policy, "AWS_Policy", "fixture managed policy"),
        (role_managed_policy, "AWS_Policy", "fixture role managed policy"),
        (saml_provider, "AWS_SAMLProvider", "fixture SAML provider"),
        (oidc_provider, "AWS_OIDCProvider", "fixture OIDC provider"),
        (lambda_primitive_user, "AWS_User", "Lambda primitive user"),
        (lambda_configuration_user, "AWS_User", "Lambda configuration user"),
        (lambda_write_user, "AWS_User", "Lambda write user"),
    ):
        report.check(f"found {description} node", node(arn, kind))

    for suite, arn, kind, description in (
        ("lambda", lambda_function, "AWS_LambdaFunction", "fixture Lambda function"),
        ("ssm", ssm_parameter, "AWS_SSMParameter", "fixture SSM parameter"),
        ("s3", bucket, "AWS_S3Bucket", "fixture S3 bucket"),
        ("s3", fixture_object, "AWS_S3Object", "fixture S3 object"),
    ):
        report.use_suite(suite)
        report.check(f"found {description} node", node(arn, kind))

    report.use_suite("cloudformation")
    primary_stack_id = fixture_stack_id(PRIMARY_ACCOUNT, PRIMARY_STACK)
    secondary_stack_id = fixture_stack_id(SECONDARY_ACCOUNT, SECONDARY_STACK)
    report.check(
        "found primary CloudFormation stack node",
        bool(primary_stack_id),
    )
    report.check(
        "found secondary CloudFormation stack node",
        bool(secondary_stack_id),
    )

    stackset_id = fixture_stackset_id(PRIMARY_ACCOUNT, STACKSET)
    report.check(
        "found primary CloudFormation StackSet node",
        bool(stackset_id),
    )

    kms_key_id = node_id_by_fixture(
        "AWS_KMSKey",
        PRIMARY_ACCOUNT,
        names=(KMS_ALIAS,),
        required_properties={"key_state": "Enabled"},
    )
    ec2_instance_id = node_id_by_fixture(
        "AWS_EC2Instance",
        PRIMARY_ACCOUNT,
        names=(EC2_INSTANCE,),
        required_properties={"state": "running"},
    )
    eks_nodegroup_id = node_id_by_fixture(
        "AWS_EKSNodeGroup",
        PRIMARY_ACCOUNT,
        names=(EKS_NODEGROUP,),
        arn_fragments=(f":nodegroup/{EKS_CLUSTER}/{EKS_NODEGROUP}/",),
    )

    report.use_suite("kms")
    report.check("found fixture KMS key node", bool(kms_key_id))
    report.use_suite("ec2")
    report.check("found fixture EC2 instance node", bool(ec2_instance_id))
    report.check("found compute role node", node(compute_role, "AWS_Role"))
    report.use_suite("ssm")
    report.check("found SSM managed-instance node", bool(ec2_instance_id))
    report.use_suite("eks")
    report.check("found fixture EKS cluster node", node(eks_cluster, "AWS_EKSCluster"))
    report.check("found fixture EKS node group node", bool(eks_nodegroup_id))
    report.check("found compute role node", node(compute_role, "AWS_Role"))
    report.check("found IRSA role node", node(eks_irsa_role, "AWS_Role"))
    report.check(
        "found Pod Identity role node", node(eks_pod_identity_role, "AWS_Role")
    )
    report.check(
        "found complete Pod Identity caller node",
        node(eks_pod_identity_complete, "AWS_User"),
    )
    report.check(
        "found missing-PassRole Pod Identity caller node",
        node(eks_pod_identity_no_pass_role, "AWS_User"),
    )
    report.check(
        "found missing-cluster-access Pod Identity caller node",
        node(eks_pod_identity_no_cluster_access, "AWS_User"),
    )

    print("Live resource-state edge invariants")
    pending_deletion_key_ids = {
        item["id"]
        for item in nodes
        if "AWS_KMSKey" in item.get("kinds", [])
        and item.get("properties", {}).get("key_state")
        in {"PendingDeletion", "PendingReplicaDeletion"}
    }
    aws_managed_key_ids = {
        item["id"]
        for item in nodes
        if "AWS_KMSKey" in item.get("kinds", [])
        and item.get("properties", {}).get("key_manager") == "AWS"
    }
    report.use_suite("kms")
    check_no_edges_to_nodes(
        "pending-deletion KMS key has no usable capability edge",
        pending_deletion_key_ids,
        KMS_KEY_CAPABILITY_EDGE_KINDS,
    )
    check_no_edges_to_nodes(
        "AWS-managed KMS key has no direct capability edge",
        aws_managed_key_ids,
        KMS_KEY_CAPABILITY_EDGE_KINDS,
    )

    print("Required structural and authorization edges")
    for suite, start, end, kind, description in (
        (
            "iam",
            primary_root,
            reader,
            "AWS_Contains",
            "primary account contains reader",
        ),
        ("iam", primary_root, role, "AWS_Contains", "primary account contains role"),
        (
            "iam",
            secondary_root,
            external,
            "AWS_Contains",
            "secondary account contains external user",
        ),
        (
            "s3",
            primary_root,
            bucket,
            "AWS_Contains",
            "primary account contains fixture bucket",
        ),
        (
            "s3",
            bucket,
            fixture_object,
            "AWS_Contains",
            "bucket contains fixture object",
        ),
        ("iam", role, external, "AWS_Trusts", "role trusts secondary user"),
        ("iam", external, role, "AWS_TrustedBy", "secondary user is trusted by role"),
        (
            "iam",
            external,
            role,
            "AWS_CanAssumeRole",
            "secondary user can assume primary role",
        ),
        (
            "iam",
            principal_tag_allowed,
            principal_tag_target,
            "AWS_CanAssumeRole",
            "persistent role tag satisfies cross-account PrincipalTag trust",
        ),
        (
            "iam",
            direct_trust_allowed,
            direct_trust_target,
            "AWS_CanAssumeRole",
            "exact same-account trust grants AssumeRole without an identity Allow",
        ),
        (
            "iam",
            direct_trust_boundary_allowed,
            direct_trust_target,
            "AWS_CanAssumeRole",
            "a permissions boundary that allows AssumeRole preserves exact-principal trust",
        ),
        ("s3", reader, bucket, "AWS_CanListBucket", "primary reader can list bucket"),
        (
            "s3",
            reader,
            fixture_object,
            "AWS_CanGetObject",
            "primary reader can read object",
        ),
        (
            "s3",
            external,
            fixture_object,
            "AWS_CanGetObject",
            "secondary user can read object cross-account",
        ),
    ):
        report.use_suite(suite)
        report.check(description, edge(start, end, kind))

    report.use_suite("iam")
    check_edges(
        "primary account contains IAM and federation fixture",
        primary_root,
        operator,
        ("AWS_Contains",),
    )
    for suite, contained, description in (
        ("iam", primary_denied, "primary negative-control user"),
        ("iam", target_user, "target user"),
        ("iam", target_group, "target group"),
        ("iam", target_role, "target role"),
        ("iam", managed_policy, "managed policy"),
        ("iam", role_managed_policy, "role managed policy"),
        ("iam", saml_provider, "SAML provider"),
        ("iam", oidc_provider, "OIDC provider"),
        ("lambda", lambda_function, "Lambda function"),
        ("ssm", ssm_parameter, "SSM parameter"),
    ):
        report.use_suite(suite)
        report.check(
            f"primary account contains {description}",
            edge(primary_root, contained, "AWS_Contains"),
        )
    report.use_suite("cloudformation")
    report.check(
        "primary account contains StackSet",
        edge(primary_root, stackset_id, "AWS_Contains"),
    )
    report.use_suite("iam")
    report.check(
        "secondary account contains negative-control user",
        edge(secondary_root, secondary_denied, "AWS_Contains"),
    )
    report.check(
        "target user is a group member", edge(target_user, target_group, "AWS_MemberOf")
    )
    report.check(
        "target group has target user", edge(target_group, target_user, "AWS_HasMember")
    )
    report.check(
        "target user has managed policy",
        edge(target_user, managed_policy, "AWS_HasPolicy"),
    )
    report.check(
        "target group has managed policy",
        edge(target_group, managed_policy, "AWS_HasPolicy"),
    )
    report.check(
        "target role has managed policy",
        edge(target_role, role_managed_policy, "AWS_HasPolicy"),
    )
    report.check(
        "managed policy is attached to target user",
        edge(managed_policy, target_user, "AWS_AttachedTo"),
    )
    report.check(
        "managed policy is attached to target group",
        edge(managed_policy, target_group, "AWS_AttachedTo"),
    )
    report.check(
        "role managed policy is attached to target role",
        edge(role_managed_policy, target_role, "AWS_AttachedTo"),
    )
    report.use_suite("iam")
    report.check(
        "target role trusts SAML provider",
        edge(target_role, saml_provider, "AWS_TrustsSAMLProvider"),
    )
    report.check(
        "target role trusts OIDC provider",
        edge(target_role, oidc_provider, "AWS_TrustsOIDCProvider"),
    )
    report.use_suite("lambda")
    report.check(
        "Lambda function runs as target role",
        edge(lambda_function, target_role, "AWS_RunsAs"),
    )
    report.use_suite("iam")
    report.check(
        "primary account has external role trust",
        edge(primary_root, secondary_root, "AWS_HasExternalRoleTrust"),
    )

    print("IAM manipulation edges")
    report.use_suite("iam")
    check_edges(
        "operator can manipulate target group",
        operator,
        target_group,
        (
            "AWS_CanAddUserToGroup",
            "AWS_CanAttachGroupPolicy",
            "AWS_CanPutGroupPolicy",
            "AWS_CanDeleteGroupPolicy",
            "AWS_CanDetachGroupPolicy",
            "AWS_CanDeleteGroup",
            "AWS_CanRemoveUserFromGroup",
        ),
    )
    check_edges(
        "operator can manipulate target user",
        operator,
        target_user,
        (
            "AWS_CanAttachUserPolicy",
            "AWS_CanPutUserPolicy",
            "AWS_CanDeleteUserPolicy",
            "AWS_CanDetachUserPolicy",
            "AWS_CanDeleteUser",
            "AWS_CanPutUserPermissionsBoundary",
            "AWS_CanDeleteUserPermissionsBoundary",
        ),
    )
    check_edges(
        "operator can manipulate target role",
        operator,
        target_role,
        (
            "AWS_CanAttachRolePolicy",
            "AWS_CanPutRolePolicy",
            "AWS_CanDeleteRolePolicy",
            "AWS_CanDetachRolePolicy",
            "AWS_CanPutRolePermissionsBoundary",
            "AWS_CanDeleteRolePermissionsBoundary",
        ),
    )
    check_edges(
        "operator can version managed policy",
        operator,
        managed_policy,
        ("AWS_CanSetDefaultPolicyVersion", "AWS_CanCreatePolicyVersion"),
    )
    check_edges(
        "operator can create or escalate identities",
        operator,
        primary_root,
        (
            "AWS_CanCreateGroup",
            "AWS_CanAttachRolePolicyWildcard",
            "AWS_CanPutRolePolicyWildcard",
            "AWS_CanCreateUser",
            "AWS_CanUpdateSelfPolicy",
            "AWS_CanUpdateOtherPolicy",
            "AWS_CanCreateAndAccessAdminUser",
        ),
    )

    print("Credential manipulation edges")
    report.use_suite("iam")
    check_edges(
        "operator can manipulate target user credentials",
        operator,
        target_user,
        (
            "AWS_CanCreateAccessKey",
            "AWS_CanDeleteAccessKey",
            "AWS_CanUpdateAccessKey",
            "AWS_CanCreateLoginProfile",
            "AWS_CanUpdateLoginProfile",
            "AWS_CanDeleteLoginProfile",
            "AWS_CanCreateServiceSpecificCredential",
            "AWS_CanResetServiceSpecificCredential",
            "AWS_CanDeleteServiceSpecificCredential",
            "AWS_CanUploadSSHPublicKey",
            "AWS_CanDeleteSSHPublicKey",
            "AWS_CanUpdateSSHPublicKey",
            "AWS_CanDeactivateMFADevice",
            "AWS_CanDeleteVirtualMFADevice",
            "AWS_CanResyncMFADevice",
            "AWS_CanEnableMFADevice",
            "AWS_CanCreateVirtualMFADevice",
        ),
    )

    print("Role trust and federation edges")
    report.use_suite("iam")
    check_edges(
        "operator role/federation account edges",
        operator,
        primary_root,
        (
            "AWS_CanCreateRole",
            "AWS_CanCreateSAMLProvider",
            "AWS_CanCreateOIDCProvider",
            "AWS_CanCreateAndAssumeAdminRole",
            "AWS_CanCreateAndPassAdminRole",
        ),
    )
    check_edges(
        "operator role/federation target edges",
        operator,
        target_role,
        (
            "AWS_CanDeleteRole",
            "AWS_CanAssumeRole",
            "AWS_CanUpdateAssumeRolePolicy",
            "AWS_CanUpdateAssumeRolePolicyAndAssume",
            "AWS_CanCreateOIDCProviderAndAssumeRole",
            "AWS_CanCreateSAMLProviderAndAssumeRole",
            "AWS_CanPassRoleToService",
        ),
    )
    check_edges(
        "operator SAML provider edges",
        operator,
        saml_provider,
        ("AWS_CanUpdateSAMLProvider", "AWS_CanDeleteSAMLProvider"),
    )
    check_edges(
        "operator OIDC provider edges",
        operator,
        oidc_provider,
        (
            "AWS_CanUpdateOIDCProviderThumbprint",
            "AWS_CanAddClientIDToOIDCProvider",
            "AWS_CanRemoveClientIDFromOIDCProvider",
            "AWS_CanDeleteOIDCProvider",
        ),
    )
    check_edges(
        "operator token edges",
        operator,
        operator,
        ("AWS_CanGetFederationToken", "AWS_CanGetSessionToken"),
    )
    report.check(
        "SAML provider can assume target role",
        edge(saml_provider, target_role, "AWS_CanAssumeRoleWithSAML"),
    )
    report.check(
        "OIDC provider can assume target role",
        edge(oidc_provider, target_role, "AWS_CanAssumeRoleWithWebIdentity"),
    )

    print("S3 primitive and meta edges")
    report.use_suite("s3")
    check_edges(
        "reader bucket primitives",
        reader,
        bucket,
        (
            "AWS_CanDeleteBucket",
            "AWS_CanDeleteBucketPolicy",
            "AWS_CanGetBucketPolicy",
            "AWS_CanListBucket",
            "AWS_CanPutBucketACL",
            "AWS_CanPutBucketOwnershipControls",
            "AWS_CanPutBucketPolicy",
            "AWS_CanPutBucketPublicAccessBlock",
            "AWS_CanPutObject",
        ),
    )
    check_edges(
        "reader object primitives",
        reader,
        fixture_object,
        (
            "AWS_CanDeleteObject",
            "AWS_CanGetObject",
            "AWS_CanPutObject",
            "AWS_CanPutObjectACL",
        ),
    )
    report.check(
        "ACL reader can get bucket ACL",
        edge(s3_acl_reader, bucket, "AWS_CanGetBucketACL"),
    )
    report.check(
        "ACL reader can get object ACL",
        edge(s3_acl_reader, fixture_object, "AWS_CanGetObjectACL"),
    )
    report.check(
        "reader can list all buckets",
        edge(reader, primary_root, "AWS_CanListAllMyBuckets"),
    )
    report.check(
        "reader can update account public access block",
        edge(reader, primary_root, "AWS_CanPutAccountPublicAccessBlock"),
    )
    report.check("bucket-all meta edge", edge(s3_bucket_all, bucket, "AWS_S3BucketAll"))
    report.check(
        "bucket-write meta edge", edge(s3_bucket_write, bucket, "AWS_S3BucketWrite")
    )
    report.check(
        "bucket-read meta edge", edge(s3_bucket_read, bucket, "AWS_S3BucketRead")
    )
    report.check(
        "object-all meta edge", edge(s3_object_all, fixture_object, "AWS_S3ObjectAll")
    )
    report.check(
        "object-write meta edge",
        edge(s3_object_write, fixture_object, "AWS_S3ObjectWrite"),
    )
    report.check(
        "object-read meta edge",
        edge(s3_object_read, fixture_object, "AWS_S3ObjectRead"),
    )

    print("CloudFormation authorization edges")
    report.use_suite("cloudformation")
    report.check(
        "operator can create CloudFormation stack",
        edge(operator, primary_root, "AWS_CanCreateCloudFormationStack"),
    )
    report.check(
        "operator can create CloudFormation StackSet",
        edge(operator, primary_root, "AWS_CanCreateCloudFormationStackSet"),
    )
    report.check(
        "operator can update primary stack",
        edge(operator, primary_stack_id, "AWS_CanUpdateCloudFormationStack"),
    )
    report.check(
        "operator can execute primary change set",
        edge(operator, primary_stack_id, "AWS_CanExecuteCloudFormationChangeSet"),
    )
    report.check(
        "operator can update StackSet",
        edge(operator, stackset_id, "AWS_CanUpdateCloudFormationStackSet"),
    )

    print("Lambda authorization edges")
    report.use_suite("lambda")
    check_edges(
        "Lambda primitive user capabilities",
        lambda_primitive_user,
        lambda_function,
        (
            "AWS_CanAddLambdaPermission",
            "AWS_CanCreateLambdaEventSource",
            "AWS_CanDeleteLambdaFunction",
            "AWS_CanInvokeLambdaFunction",
            "AWS_CanRemoveLambdaPermission",
            "AWS_CanUpdateLambdaCode",
            "AWS_CanUpdateLambdaURLConfig",
        ),
    )
    report.check(
        "Lambda configuration user can update configuration",
        edge(
            lambda_configuration_user,
            lambda_function,
            "AWS_CanUpdateLambdaConfiguration",
        ),
    )
    report.check(
        "operator can create Lambda function",
        edge(operator, primary_root, "AWS_CanCreateLambdaFunction"),
    )
    report.check(
        "operator receives Lambda-all meta edge",
        edge(operator, lambda_function, "AWS_LambdaFunctionAll"),
    )
    report.check(
        "Lambda write user receives write meta edge",
        edge(lambda_write_user, lambda_function, "AWS_LambdaFunctionWrite"),
    )
    report.check(
        "secondary user can invoke function cross-account",
        edge(external, lambda_function, "AWS_CanInvokeLambdaFunction"),
    )

    print("SSM authorization edges")
    report.use_suite("ssm")
    check_edges(
        "operator SSM account edges",
        operator,
        primary_root,
        (
            "AWS_CanCreateSSMAssociation",
            "AWS_CanCreateSSMDocument",
            "AWS_CanStartSSMAutomationExecution",
        ),
    )
    check_edges(
        "operator SSM parameter edges",
        operator,
        ssm_parameter,
        ("AWS_CanGetParameter", "AWS_CanPutParameter", "AWS_CanDeleteParameter"),
    )

    print("KMS authorization edges")
    report.use_suite("kms")
    check_edges(
        "KMS primitive user capabilities",
        kms_primitive_user,
        kms_key_id,
        (
            "AWS_CanCreateKMSGrant",
            "AWS_CanDecryptKMSKey",
            "AWS_CanDisableKMSKey",
            "AWS_CanEncryptKMSKey",
            "AWS_CanModifyKMSKeyPolicy",
            "AWS_CanScheduleKMSKeyDeletion",
            "AWS_CanSelfGrantKMSOps",
        ),
    )
    report.check(
        "KMS generate user can generate data keys",
        edge(kms_generate_user, kms_key_id, "AWS_CanGenerateKMSDataKey"),
    )
    report.check(
        "operator can list KMS keys", edge(operator, primary_root, "AWS_CanListKMSKeys")
    )
    report.check(
        "operator receives KMS-all meta edge",
        edge(operator, kms_key_id, "AWS_KMSKeyAll"),
    )
    report.check(
        "KMS read user receives KMS-read meta edge",
        edge(kms_read_user, kms_key_id, "AWS_KMSKeyRead"),
    )

    print("EC2 and SSM managed-instance authorization edges")
    report.use_suite("ec2")
    report.check(
        "operator can run EC2 instances",
        edge(operator, primary_root, "AWS_CanRunInstances"),
    )
    report.check(
        "operator can request EC2 spot instances",
        edge(operator, primary_root, "AWS_CanRequestSpotInstances"),
    )
    check_edges(
        "operator EC2 instance capabilities",
        operator,
        ec2_instance_id,
        (
            "AWS_CanAssociateIAMInstanceProfile",
            "AWS_CanCreateImage",
            "AWS_CanCreateSnapshot",
            "AWS_CanDisassociateIAMInstanceProfile",
            "AWS_CanGetPasswordData",
            "AWS_CanModifyEC2InstanceAttribute",
            "AWS_CanReplaceIAMInstanceProfileAssociation",
            "AWS_CanTerminateInstances",
            "AWS_EC2CanVolumeSwap",
        ),
    )
    report.check(
        "EC2 instance runs as compute role",
        edge(ec2_instance_id, compute_role, "AWS_RunsAs"),
    )
    report.use_suite("ssm")
    check_edges(
        "operator SSM managed-instance capabilities",
        operator,
        ec2_instance_id,
        ("AWS_SSMCanSendCommand", "AWS_SSMCanStartSession"),
    )

    print("EKS authorization edges")
    report.use_suite("eks")
    report.check(
        "cluster contains managed node group",
        edge(eks_cluster, eks_nodegroup_id, "AWS_ClusterHasNodeGroup"),
    )
    report.check(
        "managed node group has compute role",
        edge(eks_nodegroup_id, compute_role, "AWS_NodeGroupHasRole"),
    )
    report.check(
        "EKS cluster can assume IRSA role",
        edge(eks_cluster, eks_irsa_role, "AWS_CanAssumeRoleViaIRSA"),
    )
    report.check(
        "EKS cluster can assume Pod Identity role",
        edge(eks_cluster, eks_pod_identity_role, "AWS_CanAssumeRoleViaPodIdentity"),
    )
    report.check(
        "operator can create and associate EKS access entry",
        edge(operator, eks_cluster, "AWS_CanCreateAndAssociateEKSAccessEntry"),
    )
    report.check(
        "operator can create EKS node group",
        edge(operator, primary_root, "AWS_CanCreateEKSNodegroup"),
    )
    report.check(
        "operator can create EKS Pod Identity association",
        edge(operator, eks_pod_identity_role, "AWS_CanCreateEKSPodIdentityAssociation"),
    )
    report.check(
        "complete EKS caller can create a usable Pod Identity association",
        edge(
            eks_pod_identity_complete,
            eks_pod_identity_role,
            "AWS_CanCreateEKSPodIdentityAssociation",
        ),
    )

    print("Representative edge properties and suppression")
    report.use_suite("iam")
    assume_properties = edge_record(operator, target_role, "AWS_CanAssumeRole").get(
        "properties", {}
    )
    report.check(
        "conditional role assumption reports trust conditions",
        bool(assume_properties.get("trust_policy_conditions")),
    )
    principal_tag_properties = edge_record(
        principal_tag_allowed, principal_tag_target, "AWS_CanAssumeRole"
    ).get("properties", {})
    report.check(
        "principal-tag role assumption reports its trust condition",
        "aws:PrincipalTag/Student"
        in principal_tag_properties.get("trust_policy_conditions", ""),
    )
    direct_trust_properties = edge_record(
        direct_trust_allowed, direct_trust_target, "AWS_CanAssumeRole"
    ).get("properties", {})
    report.check(
        "direct-trust role assumption identifies the resource-based grant",
        "direct same-account principal"
        in direct_trust_properties.get("allow_sources", ""),
    )
    pass_properties = edge_record(
        operator, target_role, "AWS_CanPassRoleToService"
    ).get("properties", {})
    report.check(
        "PassRole meta edge is traversable",
        pass_properties.get("is_traversable") is True,
    )
    report.check(
        "PassRole meta edge reports CloudFormation",
        "cloudformation" in pass_properties.get("services", ""),
    )
    report.use_suite("s3")
    bucket_all_properties = edge_record(s3_bucket_all, bucket, "AWS_S3BucketAll").get(
        "properties", {}
    )
    report.check(
        "bucket-all meta edge is traversable",
        bucket_all_properties.get("is_traversable") is True,
    )
    report.check(
        "bucket-all suppresses its ListBucket constituent",
        absent_edge(s3_bucket_all, bucket, "AWS_CanListBucket"),
    )
    report.check(
        "object-all suppresses its GetObject constituent",
        absent_edge(s3_object_all, fixture_object, "AWS_CanGetObject"),
    )
    reader_get_properties = edge_record(reader, fixture_object, "AWS_CanGetObject").get(
        "properties", {}
    )
    report.check(
        "S3 primitive retains allow sources",
        bool(reader_get_properties.get("allow_sources")),
    )
    report.check(
        "S3 primitive omits traversability",
        "is_traversable" not in reader_get_properties,
    )
    report.use_suite("lambda")
    lambda_all_properties = edge_record(
        operator, lambda_function, "AWS_LambdaFunctionAll"
    ).get("properties", {})
    report.check(
        "Lambda-all meta edge is traversable",
        lambda_all_properties.get("is_traversable") is True,
    )
    report.check(
        "Lambda-all suppresses its invoke constituent",
        absent_edge(operator, lambda_function, "AWS_CanInvokeLambdaFunction"),
    )
    report.use_suite("eks")
    pod_identity_properties = edge_record(
        eks_pod_identity_complete,
        eks_pod_identity_role,
        "AWS_CanCreateEKSPodIdentityAssociation",
    ).get("properties", {})
    report.check(
        "Pod Identity edge reports service-scoped PassRole evidence",
        bool(pod_identity_properties.get("pass_role_allow_sources")),
    )
    report.check(
        "Pod Identity edge reports cluster-admin establishment evidence",
        "create_and_associate_cluster_admin_access_entry"
        in pod_identity_properties.get("cluster_access_methods", ""),
    )

    print("Forbidden authorization edges")
    for suite, start, end, kind, description in (
        (
            "s3",
            primary_denied,
            bucket,
            "AWS_CanListBucket",
            "primary negative-control user cannot list bucket",
        ),
        (
            "s3",
            primary_denied,
            fixture_object,
            "AWS_CanGetObject",
            "primary negative-control user cannot read object",
        ),
        (
            "s3",
            secondary_denied,
            fixture_object,
            "AWS_CanGetObject",
            "secondary negative-control user cannot read object",
        ),
        (
            "iam",
            secondary_denied,
            role,
            "AWS_CanAssumeRole",
            "secondary negative-control user cannot assume role",
        ),
        (
            "iam",
            principal_tag_denied,
            principal_tag_target,
            "AWS_CanAssumeRole",
            "identically permitted untagged role fails PrincipalTag trust",
        ),
        (
            "iam",
            direct_trust_denied,
            direct_trust_target,
            "AWS_CanAssumeRole",
            "exact same-account trust does not override an explicit Deny",
        ),
        (
            "iam",
            direct_trust_allowed,
            account_delegated_trust_target,
            "AWS_CanAssumeRole",
            "account-root delegation still requires an identity Allow",
        ),
        (
            "iam",
            direct_trust_boundary_denied,
            direct_trust_target,
            "AWS_CanAssumeRole",
            "exact same-account trust cannot bypass an implicit permissions-boundary deny",
        ),
        (
            "iam",
            direct_trust_resource_denied,
            direct_trust_target,
            "AWS_CanAssumeRole",
            "an explicit trust-policy Deny suppresses exact same-account trust",
        ),
        (
            "eks",
            eks_pod_identity_no_pass_role,
            eks_pod_identity_role,
            "AWS_CanCreateEKSPodIdentityAssociation",
            "Pod Identity path without iam:PassRole is not traversable",
        ),
        (
            "eks",
            eks_pod_identity_no_cluster_access,
            eks_pod_identity_role,
            "AWS_CanCreateEKSPodIdentityAssociation",
            "Pod Identity path without Kubernetes cluster control is not traversable",
        ),
        (
            "s3",
            external,
            bucket,
            "AWS_CanListBucket",
            "secondary cross-account user cannot list bucket",
        ),
        (
            "ssm",
            primary_denied,
            ssm_parameter,
            "AWS_CanGetParameter",
            "primary negative-control user cannot read parameter",
        ),
        (
            "lambda",
            primary_denied,
            lambda_function,
            "AWS_CanUpdateLambdaCode",
            "primary negative-control user cannot update function",
        ),
        (
            "lambda",
            external,
            lambda_function,
            "AWS_CanUpdateLambdaConfiguration",
            "secondary user cannot configure function",
        ),
        (
            "lambda",
            lambda_primitive_user,
            lambda_function,
            "AWS_LambdaFunctionWrite",
            "incomplete Lambda primitive bundle does not create a write meta edge",
        ),
        (
            "ec2",
            eks_service_role,
            ec2_instance_id,
            "AWS_CanTerminateInstances",
            "EKS service role cannot terminate standalone fixture instance",
        ),
    ):
        report.use_suite(suite)
        report.check(description, absent_edge(start, end, kind))

    report.use_suite("common")
    report.check(
        "validator asserts the intended distinct edge kinds",
        len(required_edge_kinds) == ASSERTED_EDGE_KINDS
        if args.suite == "all"
        else bool(required_edge_kinds),
    )
    report.check(
        "fixture assertions track every BHE relationship kind except Organizations",
        schema_edge_kinds - required_edge_kinds == {"AWS_HasSCP", "AWS_HasRCP"}
        if args.suite == "all"
        else required_edge_kinds <= schema_edge_kinds,
    )
    print(
        f"EDGE KINDS: {len(required_edge_kinds)}/{len(schema_edge_kinds)} distinct kinds asserted"
    )
    if args.summary is not None:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        edge_counts = Counter(item["kind"] for item in edges)
        summary = report.markdown(
            edge_counts, required_edge_kinds, edge_assertions, len(schema_edge_kinds)
        )
        args.summary.write_text(summary, encoding="utf-8")
        print()
        print(summary)
    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
