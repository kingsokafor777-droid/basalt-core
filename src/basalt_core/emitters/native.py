"""Native Basalt emitters.

``basalt`` is the lossless round-trip format. ``jsonl`` flattens each finding onto one
line with derived fields materialized, which is what ``basalt-warehouse`` loads: DuckDB
reads newline-delimited JSON directly and derived columns should not be recomputed at
query time.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Finding, ScanResult
from .base import Emitter, register_emitter

__all__ = ["JsonLinesEmitter", "NativeEmitter"]


@register_emitter
class NativeEmitter(Emitter):
    """Lossless Basalt document. Round-trips through ``ScanResult.model_validate``."""

    format = "basalt"
    extension = "json"

    def emit(self, result: ScanResult) -> dict[str, Any]:
        return result.model_dump(mode="json")


@register_emitter
class JsonLinesEmitter(Emitter):
    """One flattened finding per line, with derived fields materialized."""

    format = "jsonl"
    extension = "jsonl"
    media_type = "application/x-ndjson"

    def emit(self, result: ScanResult) -> list[dict[str, Any]]:
        return [_flatten(f, result) for f in result.findings]

    def emit_json(self, result: ScanResult, indent: int | None = None) -> str:  # noqa: ARG002
        # indent is ignored by contract: NDJSON must be exactly one record per line.
        return "\n".join(json.dumps(row, default=str) for row in self.emit(result))


def _flatten(finding: Finding, result: ScanResult) -> dict[str, Any]:
    risk = finding.risk
    return {
        "fingerprint": finding.fingerprint,
        "schema_version": finding.schema_version,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "severity_rank": finding.severity.rank,
        "risk_score": risk.value,
        "risk_band": risk.band,
        "exposure": finding.exposure.value,
        "exploitability": finding.exploitability.value,
        "state": finding.state.value,
        "provider": finding.resource.provider.value,
        "resource_urn": finding.resource.urn,
        "resource_uid": finding.resource.uid,
        "resource_type": finding.resource.resource_type,
        "resource_name": finding.resource.name,
        "account": finding.resource.account,
        "region": finding.resource.region,
        "resource_tags": finding.resource.tags,
        "control_ids": finding.control_ids,
        "frameworks": sorted({c.split(":", 1)[0] for c in finding.control_ids}),
        "location_path": finding.location.path if finding.location else None,
        "location_start_line": finding.location.start_line if finding.location else None,
        "remediation_summary": finding.remediation.summary if finding.remediation else None,
        "has_iac_patch": bool(finding.remediation and finding.remediation.iac_patch),
        "tags": finding.tags,
        "scanner": finding.scanner,
        "scanner_version": finding.scanner_version,
        "scan_account": result.metadata.account,
        "observed_at": finding.observed_at.isoformat(),
    }
