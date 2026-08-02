from __future__ import annotations

import json

import pytest

from basalt_core import ScanResult, available_formats, get_emitter
from basalt_core.emitters.ocsf import COMPLIANCE_FINDING_CLASS_UID, OCSF_VERSION
from basalt_core.emitters.sarif import SARIF_VERSION


class TestRegistry:
    def test_all_formats_registered(self) -> None:
        assert set(available_formats()) == {"sarif", "ocsf", "basalt", "jsonl"}

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(KeyError, match="unknown format"):
            get_emitter("xml")

    def test_lookup_is_case_insensitive(self) -> None:
        assert get_emitter("SARIF").format == "sarif"


class TestSarif:
    @pytest.fixture
    def doc(self, scan_result: ScanResult) -> dict:
        return get_emitter("sarif").emit(scan_result)

    def test_version_and_schema(self, doc: dict) -> None:
        assert doc["version"] == SARIF_VERSION
        assert doc["$schema"].endswith("sarif-2.1.0.json")

    def test_single_run(self, doc: dict) -> None:
        assert len(doc["runs"]) == 1

    def test_driver_metadata(self, doc: dict) -> None:
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "basalt-aws"
        assert driver["version"] == "0.1.0"

    def test_one_rule_per_unique_rule_id(self, doc: dict) -> None:
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len({r["id"] for r in rules}) == len(rules) == 3

    def test_rule_index_points_at_right_rule(self, doc: dict) -> None:
        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_severity_maps_to_level(self, doc: dict) -> None:
        levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
        assert levels["s3.public-read"] == "error"
        assert levels["tf.open-ingress"] == "error"
        assert levels["s3.missing-tags"] == "note"

    def test_security_severity_is_numeric_string(self, doc: dict) -> None:
        for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
            value = float(rule["properties"]["security-severity"])
            assert 0.0 <= value <= 10.0

    def test_partial_fingerprints_present(self, doc: dict, scan_result: ScanResult) -> None:
        emitted = {
            r["partialFingerprints"]["basaltFingerprint/v1"] for r in doc["runs"][0]["results"]
        }
        assert emitted == {f.fingerprint for f in scan_result.findings}

    def test_location_emitted_for_iac_finding(self, doc: dict) -> None:
        result = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "tf.open-ingress")
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "network/main.tf"
        assert physical["region"]["startLine"] == 42
        assert physical["region"]["endLine"] == 48

    def test_cloud_finding_has_no_location(self, doc: dict) -> None:
        result = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "s3.public-read")
        assert "locations" not in result

    def test_invocation_reports_success(self, doc: dict) -> None:
        assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True

    def test_invocation_reports_errors(self, scan_result: ScanResult) -> None:
        broken = scan_result.model_copy(
            update={
                "metadata": scan_result.metadata.model_copy(update={"errors": ["AccessDenied"]})
            }
        )
        run = get_emitter("sarif").emit(broken)["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is False
        assert (
            run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
            == "AccessDenied"
        )

    def test_help_markdown_includes_remediation(self, doc: dict) -> None:
        rule = next(
            r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "s3.public-read"
        )
        assert "### Remediation" in rule["help"]["markdown"]
        assert "### Controls" in rule["help"]["markdown"]

    def test_serializes_to_json(self, scan_result: ScanResult) -> None:
        json.loads(get_emitter("sarif").emit_json(scan_result))


class TestOcsf:
    @pytest.fixture
    def events(self, scan_result: ScanResult) -> list[dict]:
        return get_emitter("ocsf").emit(scan_result)

    def test_one_event_per_finding(self, events: list[dict], scan_result: ScanResult) -> None:
        assert len(events) == len(scan_result.findings)

    def test_class_and_category(self, events: list[dict]) -> None:
        for event in events:
            assert event["class_uid"] == COMPLIANCE_FINDING_CLASS_UID
            assert event["category_uid"] == 2

    def test_type_uid_convention(self, events: list[dict]) -> None:
        for event in events:
            assert event["type_uid"] == event["class_uid"] * 100 + event["activity_id"]

    def test_schema_version(self, events: list[dict]) -> None:
        assert events[0]["metadata"]["version"] == OCSF_VERSION

    def test_severity_ids_in_range(self, events: list[dict]) -> None:
        for event in events:
            assert 1 <= event["severity_id"] <= 5

    def test_critical_maps_to_five(self, events: list[dict]) -> None:
        event = next(e for e in events if e["compliance"]["control"] == "s3.public-read")
        assert event["severity_id"] == 5

    def test_time_is_epoch_millis(self, events: list[dict]) -> None:
        assert events[0]["time"] == 1785585600000

    def test_finding_uid_is_fingerprint(self, events: list[dict], scan_result) -> None:
        assert events[0]["finding_info"]["uid"] == scan_result.findings[0].fingerprint

    def test_compliance_standards_derived_from_controls(self, events: list[dict]) -> None:
        event = next(e for e in events if e["compliance"]["control"] == "s3.public-read")
        assert event["compliance"]["standards"] == ["cis-aws", "nist-800-53-r5"]

    def test_open_finding_is_fail(self, events: list[dict]) -> None:
        assert events[0]["compliance"]["status"] == "Fail"

    def test_account_omitted_when_absent(self, events: list[dict]) -> None:
        event = next(e for e in events if e["compliance"]["control"] == "tf.open-ingress")
        assert "account" not in event["cloud"]

    def test_unmapped_carries_basalt_extensions(self, events: list[dict]) -> None:
        basalt = events[0]["unmapped"]["basalt"]
        assert basalt["risk_score"] == 90
        assert basalt["risk_band"] == "critical"
        assert basalt["resource_urn"].startswith("urn:basalt:aws:")

    def test_remediation_included_when_present(self, events: list[dict]) -> None:
        assert "remediation" in events[0]
        assert events[0]["remediation"]["kb_article_list"]

    def test_serializes_to_json(self, scan_result: ScanResult) -> None:
        json.loads(get_emitter("ocsf").emit_json(scan_result))


class TestNative:
    def test_roundtrips_losslessly(self, scan_result: ScanResult) -> None:
        payload = get_emitter("basalt").emit_json(scan_result)
        restored = ScanResult.model_validate(json.loads(payload))
        assert restored.model_dump(mode="json") == scan_result.model_dump(mode="json")


class TestJsonLines:
    def test_one_line_per_finding(self, scan_result: ScanResult) -> None:
        lines = get_emitter("jsonl").emit_json(scan_result).splitlines()
        assert len(lines) == 3
        for line in lines:
            json.loads(line)

    def test_derived_fields_materialized(self, scan_result: ScanResult) -> None:
        row = json.loads(get_emitter("jsonl").emit_json(scan_result).splitlines()[0])
        assert row["risk_score"] == 90
        assert row["risk_band"] == "critical"
        assert row["severity_rank"] == 4
        assert row["frameworks"] == ["cis-aws", "nist-800-53-r5"]
        assert row["has_iac_patch"] is True

    def test_indent_is_ignored(self, scan_result: ScanResult) -> None:
        assert len(get_emitter("jsonl").emit_json(scan_result, indent=2).splitlines()) == 3

    def test_location_columns_null_for_cloud_findings(self, scan_result: ScanResult) -> None:
        row = json.loads(get_emitter("jsonl").emit_json(scan_result).splitlines()[0])
        assert row["location_path"] is None
