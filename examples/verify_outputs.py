"""Verify that emitted documents satisfy the guarantees each format promises.

Run by the CI contract job after ``basalt convert`` has produced every format. This is
deliberately separate from the unit tests: it exercises the installed console script and
the real files on disk, which is the path a user actually takes.

    python examples/verify_outputs.py /tmp
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXPECTED_FINDINGS = 5


def _fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_sarif(path: Path) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("version") != "2.1.0":
        _fail(f"sarif version is {doc.get('version')!r}, expected '2.1.0'")
    runs = doc.get("runs", [])
    if len(runs) != 1:
        _fail(f"expected exactly one sarif run, got {len(runs)}")
    run = runs[0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    if len(results) != EXPECTED_FINDINGS:
        _fail(f"expected {EXPECTED_FINDINGS} sarif results, got {len(results)}")
    for result in results:
        if rules[result["ruleIndex"]]["id"] != result["ruleId"]:
            _fail(f"ruleIndex does not resolve to ruleId for {result['ruleId']}")
        if not result["partialFingerprints"].get("basaltFingerprint/v1"):
            _fail(f"missing partial fingerprint on {result['ruleId']}")
        if result["level"] not in {"error", "warning", "note", "none"}:
            _fail(f"invalid sarif level {result['level']!r}")
    for rule in rules:
        severity = float(rule["properties"]["security-severity"])
        if not 0.0 <= severity <= 10.0:
            _fail(f"security-severity {severity} out of range on {rule['id']}")
    print(f"  sarif   ok  ({len(results)} results, {len(rules)} rules)")


def check_ocsf(path: Path) -> None:
    events = json.loads(path.read_text(encoding="utf-8"))
    if len(events) != EXPECTED_FINDINGS:
        _fail(f"expected {EXPECTED_FINDINGS} ocsf events, got {len(events)}")
    for event in events:
        if event["class_uid"] != 2003:
            _fail(f"expected class_uid 2003, got {event['class_uid']}")
        if event["category_uid"] != 2:
            _fail(f"expected category_uid 2, got {event['category_uid']}")
        if event["type_uid"] != event["class_uid"] * 100 + event["activity_id"]:
            _fail(f"type_uid does not follow the OCSF convention: {event['type_uid']}")
        if not 1 <= event["severity_id"] <= 5:
            _fail(f"severity_id {event['severity_id']} out of range")
        if not event["finding_info"]["uid"]:
            _fail("finding_info.uid is empty")
    print(f"  ocsf    ok  ({len(events)} events)")


def check_jsonl(path: Path) -> None:
    rows = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if len(rows) != EXPECTED_FINDINGS:
        _fail(f"expected {EXPECTED_FINDINGS} jsonl rows, got {len(rows)}")
    required = {"fingerprint", "risk_score", "risk_band", "severity_rank", "resource_urn"}
    for row in rows:
        missing = required - row.keys()
        if missing:
            _fail(f"jsonl row missing derived columns: {sorted(missing)}")
        if not 0 <= row["risk_score"] <= 100:
            _fail(f"risk_score {row['risk_score']} out of range")
    if len({row["fingerprint"] for row in rows}) != len(rows):
        _fail("duplicate fingerprints in jsonl output")
    print(f"  jsonl   ok  ({len(rows)} rows)")


def check_native(path: Path) -> None:
    from basalt_core import ScanResult

    doc = json.loads(path.read_text(encoding="utf-8"))
    restored = ScanResult.model_validate(doc)
    if restored.model_dump(mode="json") != doc:
        _fail("native format did not round-trip losslessly")
    if len(restored.findings) != EXPECTED_FINDINGS:
        _fail(f"expected {EXPECTED_FINDINGS} findings, got {len(restored.findings)}")
    print(f"  basalt  ok  (round-trip lossless, max risk {restored.max_risk()})")


def main(directory: str) -> int:
    base = Path(directory)
    print(f"verifying emitted documents in {base}")
    check_sarif(base / "out.sarif")
    check_ocsf(base / "out.ocsf.json")
    check_jsonl(base / "out.jsonl")
    check_native(base / "out.basalt.json")
    print("all format contracts satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp"))
