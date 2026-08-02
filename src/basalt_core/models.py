"""Normalized domain model shared by every Basalt scanner and consumer.

The model is intentionally provider-neutral. An AWS IAM misconfiguration, an Azure
storage exposure and a Terraform static-analysis hit all deserialize into the same
:class:`Finding`, which is what allows downstream repositories (warehouse, dashboard,
rag, agent) to treat findings as a single stream.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ._compat import StrEnum
from .severity import Exploitability, Exposure, RiskScore, Severity, score_risk

__all__ = [
    "Evidence",
    "Finding",
    "FindingState",
    "Location",
    "Provider",
    "Remediation",
    "ResourceRef",
    "ScanMetadata",
    "ScanResult",
    "utc_now",
]

_URN_UNSAFE = re.compile(r"[^A-Za-z0-9._@/\-%]")
SCHEMA_VERSION = "1.0.0"
URN_ARITY = 7


def _escape_segment(value: str | None) -> str:
    """Make a value safe to place between URN colons.

    ``%`` is escaped first so the escaping is unambiguous, then ``:`` -- without which
    an ARN or a CloudFormation type name would inject extra separators and destroy the
    fixed arity that makes the URN parseable.
    """
    if not value:
        return "-"
    escaped = value.replace("%", "%25").replace(":", "%3A")
    return _URN_UNSAFE.sub("_", escaped)


def _unescape_segment(value: str) -> str | None:
    if value == "-":
        return None
    return value.replace("%3A", ":").replace("%25", "%")


def utc_now() -> datetime:
    """Timezone-aware UTC timestamp. Used everywhere instead of ``datetime.now()``."""
    return datetime.now(timezone.utc)


class Provider(StrEnum):
    """Origin of a finding.

    ``TERRAFORM`` and ``KUBERNETES`` are first-class rather than folded under a cloud
    provider because static IaC analysis and cluster posture have no account context.
    """

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    GITHUB = "github"
    GENERIC = "generic"


class FindingState(StrEnum):
    """Lifecycle state. Set by consumers, not by scanners.

    Scanners always emit ``OPEN``. The warehouse computes ``RESOLVED`` by observing a
    fingerprint that stopped appearing; ``SUPPRESSED`` and ``ACCEPTED`` come from
    human decisions recorded outside the scan path.
    """

    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACCEPTED = "accepted"


class ResourceRef(BaseModel):
    """A scanned resource, addressable by a normalized URN.

    The URN scheme is::

        urn:basalt:<provider>:<account>:<region>:<type>:<uid>

    Empty segments collapse to ``-`` so the URN always has a fixed arity, which keeps
    it parseable and safe as a warehouse join key.
    """

    model_config = ConfigDict(frozen=True)

    provider: Provider
    resource_type: str = Field(min_length=1, description="Native type, e.g. 'AWS::S3::Bucket'")
    uid: str = Field(min_length=1, description="Provider-native identifier or ARN")
    name: str | None = None
    account: str | None = Field(
        default=None, description="AWS account, Azure subscription, GCP project"
    )
    region: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("resource_type", "uid")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def urn(self) -> str:
        return ":".join(
            [
                "urn",
                "basalt",
                self.provider.value,
                _escape_segment(self.account),
                _escape_segment(self.region),
                _escape_segment(self.resource_type),
                _escape_segment(self.uid),
            ]
        )

    @classmethod
    def parse_urn(cls, urn: str) -> ResourceRef:
        """Rebuild a reference from its URN.

        Only the segments encoded in the URN are recovered; ``name`` and ``tags`` are
        not part of the identity and come back empty.
        """
        parts = urn.split(":")
        if len(parts) != URN_ARITY or parts[0] != "urn" or parts[1] != "basalt":
            raise ValueError(f"not a Basalt resource URN: {urn!r}")
        _, _, provider, account, region, resource_type, uid = parts
        decoded_type = _unescape_segment(resource_type)
        decoded_uid = _unescape_segment(uid)
        if not decoded_type or not decoded_uid:
            raise ValueError(f"URN is missing a resource type or uid: {urn!r}")
        return cls(
            provider=Provider(provider),
            resource_type=decoded_type,
            uid=decoded_uid,
            account=_unescape_segment(account),
            region=_unescape_segment(region),
        )


class Evidence(BaseModel):
    """Why the scanner believes the finding is true.

    Kept structured rather than free text so the RAG repo can ground citations on a
    specific observed value instead of a rendered sentence.
    """

    model_config = ConfigDict(frozen=True)

    description: str = Field(min_length=1)
    observed: Any = None
    expected: Any = None
    source: str | None = Field(
        default=None, description="API call or file that produced the observation"
    )


class Remediation(BaseModel):
    """How to fix it. ``iac_patch`` is what the agent repo consumes to open a PR."""

    model_config = ConfigDict(frozen=True)

    summary: str = Field(min_length=1)
    console_steps: list[str] = Field(default_factory=list)
    cli_command: str | None = None
    iac_patch: str | None = Field(
        default=None, description="Terraform/HCL or Kubernetes YAML fragment"
    )
    references: list[str] = Field(default_factory=list)


class Location(BaseModel):
    """Source location for static-analysis findings. Maps directly onto SARIF."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = None

    @model_validator(mode="after")
    def _check_lines(self) -> Location:
        if self.start_line and self.end_line and self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class Finding(BaseModel):
    """A single normalized security or compliance observation.

    ``fingerprint`` is derived, never supplied. Two scans of an unchanged resource
    produce an identical fingerprint, which is what makes drift-over-time possible
    downstream without any scanner-side state.
    """

    model_config = ConfigDict(populate_by_name=True)

    schema_version: str = SCHEMA_VERSION
    rule_id: str = Field(min_length=1, description="Stable scanner-owned rule identifier")
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    severity: Severity
    resource: ResourceRef
    scanner: str = Field(min_length=1, description="Emitting scanner package name")
    scanner_version: str = "0.0.0"

    exposure: Exposure = Exposure.INTERNAL
    exploitability: Exploitability = Exploitability.MODERATE
    state: FindingState = FindingState.OPEN

    control_ids: list[str] = Field(
        default_factory=list, description="Control IDs, e.g. 'nist-800-53-r5:AC-6'"
    )
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: Remediation | None = None
    location: Location | None = None
    tags: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=utc_now)

    @field_validator("rule_id")
    @classmethod
    def _normalize_rule_id(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", v):
            raise ValueError(
                f"rule_id must be lowercase alphanumeric with '.', '_' or '-' (got {v!r})"
            )
        return v

    @field_validator("control_ids")
    @classmethod
    def _dedupe_controls(cls, v: list[str]) -> list[str]:
        return sorted({c.strip() for c in v if c.strip()})

    @field_validator("observed_at")
    @classmethod
    def _require_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        return v.astimezone(timezone.utc)

    @property
    def fingerprint(self) -> str:
        """Stable 32-hex identity for (rule, resource, location).

        Deliberately excludes severity, timestamps and evidence values: a rule whose
        severity is retuned must not orphan its history in the warehouse.
        """
        parts = [self.rule_id, self.resource.urn]
        if self.location:
            parts.extend([self.location.path, str(self.location.start_line or 0)])
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]

    @property
    def risk(self) -> RiskScore:
        """Deterministic 0-100 risk score with its factor breakdown."""
        return score_risk(self.severity, self.exposure, self.exploitability)


class ScanMetadata(BaseModel):
    """Provenance for a scan run."""

    model_config = ConfigDict(populate_by_name=True)

    scanner: str = Field(min_length=1)
    scanner_version: str = "0.0.0"
    provider: Provider
    account: str | None = None
    regions: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    checks_run: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


class ScanResult(BaseModel):
    """The unit every scanner returns and every consumer ingests."""

    schema_version: str = SCHEMA_VERSION
    metadata: ScanMetadata
    findings: list[Finding] = Field(default_factory=list)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def max_risk(self) -> int:
        return max((f.risk.value for f in self.findings), default=0)

    def deduplicate(self) -> ScanResult:
        """Collapse findings sharing a fingerprint, keeping the highest severity."""
        best: dict[str, Finding] = {}
        for f in self.findings:
            current = best.get(f.fingerprint)
            if current is None or f.severity.rank > current.severity.rank:
                best[f.fingerprint] = f
        ordered = sorted(best.values(), key=lambda f: (-f.risk.value, f.rule_id, f.resource.urn))
        return self.model_copy(update={"findings": ordered})
