from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from basalt_core import (
    Finding,
    FindingState,
    Location,
    Provider,
    ResourceRef,
    ScanResult,
    Severity,
)


class TestResourceUrn:
    def test_urn_has_fixed_arity_despite_colons_in_arn(self, bucket: ResourceRef) -> None:
        assert len(bucket.urn.split(":")) == 7

    def test_urn_contains_all_segments(self, bucket: ResourceRef) -> None:
        assert bucket.urn == (
            "urn:basalt:aws:123456789012:ca-central-1:AWS%3A%3AS3%3A%3ABucket:"
            "arn%3Aaws%3As3%3A%3A%3Abasalt-example-bucket"
        )

    @pytest.mark.parametrize(
        "uid",
        [
            "arn:aws:cloudtrail:ca-central-1:123456789012:trail/*",
            "bucket name with spaces",
            "key/with/slashes",
            "weird!@#$%^&*()chars",
            "unicode-café-ñ",
            "100% legitimate",
            "-",
            "trailing-",
            "a:b:c:d:e:f:g",
        ],
    )
    def test_urn_round_trips_for_arbitrary_uids(self, uid: str) -> None:
        """Escaping must be lossless, not merely safe.

        Substituting unsafe characters would silently collapse distinct resources onto
        one URN, and the URN is a join key downstream.
        """
        ref = ResourceRef(provider=Provider.AWS, resource_type="T", uid=uid)
        assert len(ref.urn.split(":")) == 7
        assert ResourceRef.parse_urn(ref.urn).uid == uid

    def test_wildcard_uid_survives_round_trip(self) -> None:
        ref = ResourceRef(
            provider=Provider.AWS,
            resource_type="AWS::CloudTrail::Trail",
            uid="arn:aws:cloudtrail:ca-central-1:123456789012:trail/*",
        )
        assert ResourceRef.parse_urn(ref.urn).uid.endswith("trail/*")

    def test_distinct_uids_never_collide(self) -> None:
        a = ResourceRef(provider=Provider.AWS, resource_type="T", uid="a*b")
        b = ResourceRef(provider=Provider.AWS, resource_type="T", uid="a_b")
        assert a.urn != b.urn

    def test_urn_round_trips(self, bucket: ResourceRef) -> None:
        parsed = ResourceRef.parse_urn(bucket.urn)
        assert parsed.uid == bucket.uid
        assert parsed.resource_type == bucket.resource_type
        assert parsed.account == bucket.account
        assert parsed.region == bucket.region
        assert parsed.provider is bucket.provider

    def test_urn_round_trips_with_missing_segments(self, tf_file: ResourceRef) -> None:
        parsed = ResourceRef.parse_urn(tf_file.urn)
        assert parsed.account is None
        assert parsed.region is None
        assert parsed.uid == tf_file.uid

    def test_literal_percent_sequence_is_escaped(self) -> None:
        """A uid that already looks percent-encoded must not be double-decoded."""
        ref = ResourceRef(provider=Provider.AWS, resource_type="T", uid="a%3Ab")
        assert ResourceRef.parse_urn(ref.urn).uid == "a%3Ab"

    @pytest.mark.parametrize(
        "bad",
        ["urn:basalt:aws:-:-:T", "arn:aws:s3:::x", "urn:other:aws:-:-:T:u"],
    )
    def test_parse_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValueError, match="Basalt resource URN"):
            ResourceRef.parse_urn(bad)

    def test_missing_segments_collapse_to_dash(self, tf_file: ResourceRef) -> None:
        assert ":-:-:" in tf_file.urn

    def test_unsafe_characters_are_replaced(self) -> None:
        ref = ResourceRef(
            provider=Provider.AZURE,
            resource_type="Microsoft.Storage/storageAccounts",
            uid="acct name with spaces",
        )
        assert " " not in ref.urn

    def test_resource_is_frozen(self, bucket: ResourceRef) -> None:
        with pytest.raises(ValidationError):
            bucket.uid = "changed"  # type: ignore[misc]

    def test_uid_is_stripped(self) -> None:
        ref = ResourceRef(provider=Provider.AWS, resource_type=" t ", uid="  x  ")
        assert (ref.resource_type, ref.uid) == ("t", "x")

    def test_empty_uid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ResourceRef(provider=Provider.AWS, resource_type="t", uid="")


class TestFingerprint:
    def test_is_stable_across_instances(self, critical_finding: Finding) -> None:
        twin = critical_finding.model_copy(deep=True)
        assert twin.fingerprint == critical_finding.fingerprint

    def test_is_32_hex_chars(self, critical_finding: Finding) -> None:
        fp = critical_finding.fingerprint
        assert len(fp) == 32
        assert all(c in "0123456789abcdef" for c in fp)

    def test_ignores_severity_retuning(self, critical_finding: Finding) -> None:
        retuned = critical_finding.model_copy(update={"severity": Severity.LOW})
        assert retuned.fingerprint == critical_finding.fingerprint

    def test_ignores_timestamp(self, critical_finding: Finding) -> None:
        later = critical_finding.model_copy(
            update={"observed_at": datetime.fromisoformat("2026-09-01T00:00:00+00:00")}
        )
        assert later.fingerprint == critical_finding.fingerprint

    def test_changes_with_rule(self, critical_finding: Finding) -> None:
        other = critical_finding.model_copy(update={"rule_id": "s3.public-write"})
        assert other.fingerprint != critical_finding.fingerprint

    def test_changes_with_resource(self, critical_finding: Finding) -> None:
        moved = critical_finding.model_copy(
            update={
                "resource": critical_finding.resource.model_copy(
                    update={"uid": "arn:aws:s3:::other"}
                )
            }
        )
        assert moved.fingerprint != critical_finding.fingerprint

    def test_changes_with_location_line(self, iac_finding: Finding) -> None:
        shifted = iac_finding.model_copy(
            update={"location": Location(path="network/main.tf", start_line=99)}
        )
        assert shifted.fingerprint != iac_finding.fingerprint


class TestFindingValidation:
    def test_rule_id_must_be_lowercase(self, bucket: ResourceRef) -> None:
        with pytest.raises(ValidationError, match="lowercase"):
            Finding(
                rule_id="S3.PublicRead",
                title="t",
                description="d",
                severity=Severity.HIGH,
                resource=bucket,
                scanner="x",
            )

    def test_rule_id_rejects_spaces(self, bucket: ResourceRef) -> None:
        with pytest.raises(ValidationError):
            Finding(
                rule_id="s3 public read",
                title="t",
                description="d",
                severity=Severity.HIGH,
                resource=bucket,
                scanner="x",
            )

    def test_control_ids_deduped_and_sorted(self, bucket: ResourceRef) -> None:
        finding = Finding(
            rule_id="a.b",
            title="t",
            description="d",
            severity=Severity.LOW,
            resource=bucket,
            scanner="x",
            control_ids=["z:2", "a:1", "z:2", "  "],
        )
        assert finding.control_ids == ["a:1", "z:2"]

    def test_naive_timestamp_rejected(self, bucket: ResourceRef) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            Finding(
                rule_id="a.b",
                title="t",
                description="d",
                severity=Severity.LOW,
                resource=bucket,
                scanner="x",
                observed_at=datetime(2026, 1, 1),
            )

    def test_defaults_to_open_state(self, critical_finding: Finding) -> None:
        assert critical_finding.state is FindingState.OPEN

    def test_location_line_order_enforced(self) -> None:
        with pytest.raises(ValidationError, match=">= start_line"):
            Location(path="a.tf", start_line=10, end_line=2)


class TestScanResult:
    def test_severity_counts_cover_all_levels(self, scan_result: ScanResult) -> None:
        counts = scan_result.severity_counts()
        assert set(counts) == {s.value for s in Severity}
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["low"] == 1

    def test_by_severity(self, scan_result: ScanResult) -> None:
        assert len(scan_result.by_severity(Severity.CRITICAL)) == 1
        assert scan_result.by_severity(Severity.INFO) == []

    def test_max_risk(self, scan_result: ScanResult) -> None:
        assert scan_result.max_risk() == 90

    def test_max_risk_of_empty_is_zero(self, scan_result: ScanResult) -> None:
        empty = scan_result.model_copy(update={"findings": []})
        assert empty.max_risk() == 0

    def test_dedupe_keeps_highest_severity(
        self, scan_result: ScanResult, critical_finding: Finding
    ) -> None:
        weaker = critical_finding.model_copy(update={"severity": Severity.LOW})
        noisy = scan_result.model_copy(update={"findings": [weaker, *scan_result.findings]})
        deduped = noisy.deduplicate()
        assert len(deduped.findings) == 3
        assert deduped.findings[0].severity is Severity.CRITICAL

    def test_dedupe_orders_by_risk_descending(self, scan_result: ScanResult) -> None:
        scores = [f.risk.value for f in scan_result.deduplicate().findings]
        assert scores == sorted(scores, reverse=True)

    def test_roundtrips_through_json(self, scan_result: ScanResult) -> None:
        restored = ScanResult.model_validate_json(scan_result.model_dump_json())
        assert [f.fingerprint for f in restored.findings] == [
            f.fingerprint for f in scan_result.findings
        ]

    def test_metadata_duration(self, scan_result: ScanResult) -> None:
        assert scan_result.metadata.duration_seconds == 0.0

    def test_duration_none_when_incomplete(self, scan_result: ScanResult) -> None:
        meta = scan_result.metadata.model_copy(update={"completed_at": None})
        assert meta.duration_seconds is None
