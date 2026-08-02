"""Emit a representative Basalt scan result on stdout.

Used by the CI contract job and as a copy-paste starting point:

    python examples/generate_example.py > scan.json
    basalt validate scan.json --strict
    basalt convert scan.json --to sarif -o results.sarif
"""

from __future__ import annotations

from datetime import datetime, timezone

from basalt_core import (
    Evidence,
    Exploitability,
    Exposure,
    Finding,
    Location,
    Provider,
    Remediation,
    ResourceRef,
    ScanMetadata,
    ScanResult,
    Severity,
)

OBSERVED_AT = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
ACCOUNT = "123456789012"
REGION = "ca-central-1"


def build() -> ScanResult:
    bucket = ResourceRef(
        provider=Provider.AWS,
        resource_type="AWS::S3::Bucket",
        uid=f"arn:aws:s3:::basalt-example-{ACCOUNT}",
        name=f"basalt-example-{ACCOUNT}",
        account=ACCOUNT,
        region=REGION,
        tags={"env": "prod", "owner": "platform"},
    )
    root_user = ResourceRef(
        provider=Provider.AWS,
        resource_type="AWS::IAM::User",
        uid=f"arn:aws:iam::{ACCOUNT}:root",
        name="root",
        account=ACCOUNT,
    )
    security_group = ResourceRef(
        provider=Provider.TERRAFORM,
        resource_type="aws_security_group",
        uid="module.network.aws_security_group.web",
    )

    findings = [
        Finding(
            rule_id="s3.public-read",
            title="S3 bucket allows public read access",
            description="The bucket ACL grants READ to the AllUsers group, exposing every "
            "object to anonymous callers.",
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
                summary="Enable S3 Block Public Access on the bucket and at the account level.",
                cli_command=(
                    f"aws s3api put-public-access-block --bucket basalt-example-{ACCOUNT} "
                    "--public-access-block-configuration BlockPublicAcls=true,"
                    "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                iac_patch=(
                    'resource "aws_s3_bucket_public_access_block" "this" {\n'
                    "  bucket                  = aws_s3_bucket.this.id\n"
                    "  block_public_acls       = true\n"
                    "  ignore_public_acls      = true\n"
                    "  block_public_policy     = true\n"
                    "  restrict_public_buckets = true\n"
                    "}"
                ),
                references=[
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                ],
            ),
            tags=["storage", "data-exposure"],
            observed_at=OBSERVED_AT,
        ),
        Finding(
            rule_id="iam.root-mfa-missing",
            title="MFA is not enabled for the root user",
            description="The account root user can authenticate with a password alone.",
            severity=Severity.HIGH,
            exposure=Exposure.EXTERNAL,
            exploitability=Exploitability.MODERATE,
            resource=root_user,
            scanner="basalt-aws",
            scanner_version="0.1.0",
            control_ids=["cis-aws:iam.root-mfa", "nist-800-53-r5:IA-2"],
            evidence=[
                Evidence(
                    description="Credential report root MFA column",
                    observed=False,
                    expected=True,
                    source="iam:GetAccountSummary",
                )
            ],
            remediation=Remediation(
                summary="Register a hardware or virtual MFA device for the root user.",
                console_steps=[
                    "Sign in as the root user",
                    "Open Security credentials",
                    "Assign an MFA device",
                ],
            ),
            tags=["identity"],
            observed_at=OBSERVED_AT,
        ),
        Finding(
            rule_id="tf.unrestricted-ssh-ingress",
            title="Security group permits SSH from anywhere",
            description="An ingress rule allows 0.0.0.0/0 on TCP port 22.",
            severity=Severity.HIGH,
            exposure=Exposure.PUBLIC,
            exploitability=Exploitability.MODERATE,
            resource=security_group,
            scanner="basalt-iac",
            scanner_version="0.1.0",
            control_ids=["cis-aws:network.no-open-admin-ports", "nist-800-53-r5:SC-7"],
            location=Location(
                path="infra/network/main.tf",
                start_line=42,
                end_line=48,
                snippet='cidr_blocks = ["0.0.0.0/0"]',
            ),
            remediation=Remediation(
                summary=(
                    "Restrict ingress to the bastion CIDR, or replace SSH entirely "
                    "with SSM Session Manager."
                ),
                iac_patch="cidr_blocks = [var.bastion_cidr]",
            ),
            tags=["network"],
            observed_at=OBSERVED_AT,
        ),
        Finding(
            rule_id="s3.versioning-disabled",
            title="Bucket versioning is disabled",
            description="Object versioning is off, so overwrites and deletions are unrecoverable.",
            severity=Severity.MEDIUM,
            exposure=Exposure.INTERNAL,
            exploitability=Exploitability.DIFFICULT,
            resource=bucket,
            scanner="basalt-aws",
            scanner_version="0.1.0",
            control_ids=["nist-800-53-r5:CP-9"],
            observed_at=OBSERVED_AT,
        ),
        Finding(
            rule_id="s3.missing-owner-tag",
            title="Bucket is missing the owner tag",
            description="Ownership metadata is required by the tagging policy.",
            severity=Severity.LOW,
            exposure=Exposure.ISOLATED,
            exploitability=Exploitability.THEORETICAL,
            resource=bucket,
            scanner="basalt-aws",
            scanner_version="0.1.0",
            control_ids=["nist-800-53-r5:CM-6"],
            observed_at=OBSERVED_AT,
        ),
    ]

    return ScanResult(
        metadata=ScanMetadata(
            scanner="basalt-aws",
            scanner_version="0.1.0",
            provider=Provider.AWS,
            account=ACCOUNT,
            regions=[REGION],
            started_at=OBSERVED_AT,
            completed_at=OBSERVED_AT,
            checks_run=len(findings),
        ),
        findings=findings,
    )


if __name__ == "__main__":
    print(build().model_dump_json(indent=2))
