"""SARIF 2.1.0 emitter.

SARIF is the format GitHub Code Scanning ingests, so any Basalt scanner can annotate
a pull request without additional glue. The mapping deliberately keeps Basalt-specific
fields under ``properties`` rather than inventing non-standard top-level keys.

Findings without a :class:`~basalt_core.models.Location` still emit validly: SARIF
permits a result with no physical location, which is the correct representation of a
cloud posture finding that has no file behind it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..models import Finding, ScanResult
from ..severity import Severity
from .base import Emitter, register_emitter

__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "SarifEmitter"]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# SARIF security-severity is a CVSS-like 0.0-10.0 string. GitHub uses it to bucket
# alerts, so the Basalt 0-100 risk score is rescaled rather than the raw severity.
_SECURITY_SEVERITY_CEILING = 10.0


@register_emitter
class SarifEmitter(Emitter):
    """Render a scan result as a SARIF 2.1.0 log."""

    format = "sarif"
    extension = "sarif"
    media_type = "application/sarif+json"

    def emit(self, result: ScanResult) -> dict[str, Any]:
        rules, rule_index = self._build_rules(result.findings)
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": result.metadata.scanner,
                            "version": result.metadata.scanner_version,
                            "informationUri": "https://github.com/kingsokafor777-droid/basalt-core",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": not result.metadata.errors,
                            "startTimeUtc": _ts(result.metadata.started_at),
                            "endTimeUtc": _ts(result.metadata.completed_at),
                            "toolExecutionNotifications": [
                                {"level": "error", "message": {"text": err}}
                                for err in result.metadata.errors
                            ],
                        }
                    ],
                    "results": [self._result(f, rule_index) for f in result.findings],
                    "properties": {
                        "provider": result.metadata.provider.value,
                        "account": result.metadata.account,
                        "regions": result.metadata.regions,
                    },
                }
            ],
        }

    def _build_rules(self, findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
        rules: list[dict[str, Any]] = []
        index: dict[str, int] = {}
        for finding in findings:
            if finding.rule_id in index:
                continue
            index[finding.rule_id] = len(rules)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": _pascal(finding.rule_id),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                    "help": {
                        "text": finding.remediation.summary
                        if finding.remediation
                        else finding.description,
                        "markdown": _help_markdown(finding),
                    },
                    "properties": {
                        "tags": sorted(
                            {"security", finding.resource.provider.value, *finding.tags}
                        ),
                        "security-severity": _security_severity(finding),
                        "basalt-severity": finding.severity.value,
                        "controls": finding.control_ids,
                    },
                }
            )
        return rules, index

    def _result(self, finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _LEVEL[finding.severity],
            "message": {"text": f"{finding.title}: {finding.description}"},
            "partialFingerprints": {"basaltFingerprint/v1": finding.fingerprint},
            "properties": {
                "resourceUrn": finding.resource.urn,
                "riskScore": finding.risk.value,
                "riskBand": finding.risk.band,
                "state": finding.state.value,
                "controls": finding.control_ids,
                "observedAt": _ts(finding.observed_at),
            },
        }
        if finding.location is not None:
            region: dict[str, Any] = {}
            if finding.location.start_line:
                region["startLine"] = finding.location.start_line
            if finding.location.end_line:
                region["endLine"] = finding.location.end_line
            if finding.location.snippet:
                region["snippet"] = {"text": finding.location.snippet}
            physical: dict[str, Any] = {"artifactLocation": {"uri": finding.location.path}}
            if region:
                physical["region"] = region
            entry["locations"] = [{"physicalLocation": physical}]
        return entry


def _security_severity(finding: Finding) -> str:
    scaled = finding.risk.value / 100 * _SECURITY_SEVERITY_CEILING
    return f"{scaled:.1f}"


def _help_markdown(finding: Finding) -> str:
    lines = [f"**{finding.title}**", "", finding.description]
    if finding.remediation:
        lines += ["", "### Remediation", finding.remediation.summary]
        if finding.remediation.cli_command:
            lines += ["", "```bash", finding.remediation.cli_command, "```"]
        if finding.remediation.references:
            lines += ["", "### References"] + [f"- {r}" for r in finding.remediation.references]
    if finding.control_ids:
        lines += ["", "### Controls"] + [f"- `{c}`" for c in finding.control_ids]
    return "\n".join(lines)


def _pascal(rule_id: str) -> str:
    return "".join(
        part.capitalize() for part in rule_id.replace(".", "-").replace("_", "-").split("-")
    )


def _ts(value: datetime | None) -> str | None:
    """SARIF requires RFC 3339 UTC timestamps."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
