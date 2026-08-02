"""OCSF emitter (Compliance Finding, class_uid 2003).

OCSF is the schema AWS Security Lake and a growing set of SIEMs consume natively.
Emitting it means Basalt findings land in an enterprise data lake without a bespoke
parser, which is the single most useful interoperability property this library has.

One event object is produced per finding. ``type_uid`` follows the OCSF convention
``class_uid * 100 + activity_id``.
"""

from __future__ import annotations

from typing import Any

from ..models import Finding, FindingState, ScanResult
from ..severity import Severity
from .base import Emitter, register_emitter

__all__ = ["COMPLIANCE_FINDING_CLASS_UID", "OCSF_VERSION", "OcsfEmitter"]

OCSF_VERSION = "1.3.0"
COMPLIANCE_FINDING_CLASS_UID = 2003
FINDINGS_CATEGORY_UID = 2
ACTIVITY_CREATE = 1

_SEVERITY_ID: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

# OCSF status_id on a finding: 1 New, 2 In Progress, 3 Suppressed, 4 Resolved.
_STATUS_ID: dict[FindingState, int] = {
    FindingState.OPEN: 1,
    FindingState.SUPPRESSED: 3,
    FindingState.ACCEPTED: 3,
    FindingState.RESOLVED: 4,
}


@register_emitter
class OcsfEmitter(Emitter):
    """Render a scan result as a list of OCSF Compliance Finding events."""

    format = "ocsf"
    extension = "json"
    media_type = "application/json"

    def emit(self, result: ScanResult) -> list[dict[str, Any]]:
        return [self._event(f, result) for f in result.findings]

    def _event(self, finding: Finding, result: ScanResult) -> dict[str, Any]:
        observed_ms = int(finding.observed_at.timestamp() * 1000)
        compliance_status = "Fail" if finding.state is FindingState.OPEN else "Other"
        event: dict[str, Any] = {
            "activity_id": ACTIVITY_CREATE,
            "activity_name": "Create",
            "category_uid": FINDINGS_CATEGORY_UID,
            "category_name": "Findings",
            "class_uid": COMPLIANCE_FINDING_CLASS_UID,
            "class_name": "Compliance Finding",
            "type_uid": COMPLIANCE_FINDING_CLASS_UID * 100 + ACTIVITY_CREATE,
            "time": observed_ms,
            "severity_id": _SEVERITY_ID[finding.severity],
            "severity": finding.severity.value.capitalize(),
            "status_id": _STATUS_ID[finding.state],
            "status": finding.state.value.capitalize(),
            "message": finding.title,
            "metadata": {
                "version": OCSF_VERSION,
                "product": {
                    "name": result.metadata.scanner,
                    "version": result.metadata.scanner_version,
                    "vendor_name": "Basalt",
                },
                "profiles": ["cloud"],
            },
            "cloud": {
                "provider": finding.resource.provider.value,
                "account": {"uid": finding.resource.account} if finding.resource.account else None,
                "region": finding.resource.region,
            },
            "finding_info": {
                "uid": finding.fingerprint,
                "title": finding.title,
                "desc": finding.description,
                "created_time": observed_ms,
                "types": ["Compliance"],
            },
            "compliance": {
                "status": compliance_status,
                "status_detail": _status_detail(finding),
                "requirements": finding.control_ids,
                "standards": sorted({c.split(":", 1)[0] for c in finding.control_ids}),
                "control": finding.rule_id,
            },
            "resources": [
                {
                    "uid": finding.resource.uid,
                    "name": finding.resource.name or finding.resource.uid,
                    "type": finding.resource.resource_type,
                    "cloud_partition": finding.resource.region,
                    "labels": [f"{k}={v}" for k, v in sorted(finding.resource.tags.items())],
                }
            ],
            "unmapped": {
                "basalt": {
                    "schema_version": finding.schema_version,
                    "resource_urn": finding.resource.urn,
                    "risk_score": finding.risk.value,
                    "risk_band": finding.risk.band,
                    "risk_explanation": finding.risk.explain(),
                    "exposure": finding.exposure.value,
                    "exploitability": finding.exploitability.value,
                    "tags": finding.tags,
                }
            },
        }
        if finding.remediation is not None:
            event["remediation"] = {
                "desc": finding.remediation.summary,
                "kb_article_list": [{"src_url": r} for r in finding.remediation.references],
            }
        if finding.location is not None:
            event["unmapped"]["basalt"]["location"] = {
                "path": finding.location.path,
                "start_line": finding.location.start_line,
                "end_line": finding.location.end_line,
            }
        if event["cloud"]["account"] is None:
            event["cloud"].pop("account")
        return event


def _status_detail(finding: Finding) -> str:
    if finding.evidence:
        first = finding.evidence[0]
        if first.expected is not None:
            return f"{first.description} (observed={first.observed!r}, expected={first.expected!r})"
        return first.description
    return finding.description
