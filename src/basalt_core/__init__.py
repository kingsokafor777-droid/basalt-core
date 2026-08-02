"""Basalt Core - the shared foundation of the Basalt cloud security platform.

Defines one normalized finding model, one deterministic risk score, one control
catalog and one scanner interface, so that every Basalt scanner produces output the
warehouse, dashboard, RAG layer and remediation agent can consume without adapters.

Quick start::

    from basalt_core import Finding, Provider, ResourceRef, Severity, get_emitter

    finding = Finding(
        rule_id="s3.public-read",
        title="S3 bucket allows public read",
        description="The bucket ACL grants READ to AllUsers.",
        severity=Severity.CRITICAL,
        resource=ResourceRef(
            provider=Provider.AWS,
            resource_type="AWS::S3::Bucket",
            uid="arn:aws:s3:::example-bucket",
            account="123456789012",
            region="ca-central-1",
        ),
        scanner="basalt-aws",
    )
    print(finding.risk.explain())
"""

from .controls import (
    Control,
    ControlCatalog,
    Framework,
    load_catalog,
    qualify,
    split_control_id,
)
from .emitters import EMITTERS, Emitter, available_formats, get_emitter, register_emitter
from .models import (
    SCHEMA_VERSION,
    Evidence,
    Finding,
    FindingState,
    Location,
    Provider,
    Remediation,
    ResourceRef,
    ScanMetadata,
    ScanResult,
    utc_now,
)
from .plugin import (
    ENTRY_POINT_GROUP,
    ScanContext,
    Scanner,
    ScannerError,
    discover_scanners,
    load_scanner,
)
from .severity import Exploitability, Exposure, RiskScore, Severity, score_risk

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    # models
    "Finding",
    "FindingState",
    "ResourceRef",
    "Evidence",
    "Remediation",
    "Location",
    "Provider",
    "ScanMetadata",
    "ScanResult",
    "utc_now",
    # severity and risk
    "Severity",
    "Exposure",
    "Exploitability",
    "RiskScore",
    "score_risk",
    # controls
    "Control",
    "Framework",
    "ControlCatalog",
    "load_catalog",
    "qualify",
    "split_control_id",
    # plugins
    "Scanner",
    "ScanContext",
    "ScannerError",
    "discover_scanners",
    "load_scanner",
    "ENTRY_POINT_GROUP",
    # emitters
    "Emitter",
    "EMITTERS",
    "get_emitter",
    "register_emitter",
    "available_formats",
]
