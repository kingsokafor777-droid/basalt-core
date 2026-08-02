from __future__ import annotations

from datetime import datetime, timezone

import pytest

from basalt_core import (
    Evidence,
    Finding,
    Location,
    Provider,
    Remediation,
    ResourceRef,
    ScanMetadata,
    ScanResult,
    Severity,
)
from basalt_core.severity import Exploitability, Exposure

FIXED_TIME = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def bucket() -> ResourceRef:
    return ResourceRef(
        provider=Provider.AWS,
        resource_type="AWS::S3::Bucket",
        uid="arn:aws:s3:::basalt-example-bucket",
        name="basalt-example-bucket",
        account="123456789012",
        region="ca-central-1",
        tags={"env": "prod", "owner": "platform"},
    )


@pytest.fixture
def tf_file() -> ResourceRef:
    return ResourceRef(
        provider=Provider.TERRAFORM,
        resource_type="aws_security_group",
        uid="module.network.aws_security_group.web",
    )


@pytest.fixture
def critical_finding(bucket: ResourceRef) -> Finding:
    return Finding(
        rule_id="s3.public-read",
        title="S3 bucket allows public read access",
        description="The bucket ACL grants READ to the AllUsers group.",
        severity=Severity.CRITICAL,
        exposure=Exposure.PUBLIC,
        exploitability=Exploitability.TRIVIAL,
        resource=bucket,
        scanner="basalt-aws",
        scanner_version="0.1.0",
        control_ids=["cis-aws:storage.bucket-public-access", "nist-800-53-r5:AC-3"],
        evidence=[
            Evidence(
                description="Bucket ACL grant",
                observed="AllUsers:READ",
                expected="no public grants",
                source="s3:GetBucketAcl",
            )
        ],
        remediation=Remediation(
            summary="Enable S3 Block Public Access on the bucket and the account.",
            cli_command="aws s3api put-public-access-block --bucket basalt-example-bucket",
            iac_patch='resource "aws_s3_bucket_public_access_block" "this" {}',
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            ],
        ),
        observed_at=FIXED_TIME,
    )


@pytest.fixture
def iac_finding(tf_file: ResourceRef) -> Finding:
    return Finding(
        rule_id="tf.open-ingress",
        title="Security group allows unrestricted ingress",
        description="Ingress rule permits 0.0.0.0/0 on port 22.",
        severity=Severity.HIGH,
        exposure=Exposure.PUBLIC,
        exploitability=Exploitability.MODERATE,
        resource=tf_file,
        scanner="basalt-iac",
        control_ids=["cis-aws:network.no-open-admin-ports"],
        location=Location(
            path="network/main.tf",
            start_line=42,
            end_line=48,
            snippet='cidr_blocks = ["0.0.0.0/0"]',
        ),
        observed_at=FIXED_TIME,
    )


@pytest.fixture
def low_finding(bucket: ResourceRef) -> Finding:
    return Finding(
        rule_id="s3.missing-tags",
        title="Bucket is missing required tags",
        description="The cost-center tag is absent.",
        severity=Severity.LOW,
        exposure=Exposure.ISOLATED,
        exploitability=Exploitability.THEORETICAL,
        resource=bucket,
        scanner="basalt-aws",
        observed_at=FIXED_TIME,
    )


@pytest.fixture
def scan_result(
    critical_finding: Finding, iac_finding: Finding, low_finding: Finding
) -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            scanner="basalt-aws",
            scanner_version="0.1.0",
            provider=Provider.AWS,
            account="123456789012",
            regions=["ca-central-1"],
            started_at=FIXED_TIME,
            completed_at=FIXED_TIME,
            checks_run=3,
        ),
        findings=[critical_finding, iac_finding, low_finding],
    )
