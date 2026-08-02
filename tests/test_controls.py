from __future__ import annotations

import json

import pytest

from basalt_core.controls import ControlCatalog, load_catalog, qualify, split_control_id


class TestQualifiedIds:
    def test_qualify(self) -> None:
        assert qualify("nist-800-53-r5", "AC-6") == "nist-800-53-r5:AC-6"

    def test_split(self) -> None:
        assert split_control_id("cis-aws:iam.root-mfa") == ("cis-aws", "iam.root-mfa")

    @pytest.mark.parametrize("bad", ["AC-6", ":AC-6", "nist:", ""])
    def test_split_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValueError, match="framework:control"):
            split_control_id(bad)


class TestBuiltinCatalog:
    def test_loads(self) -> None:
        assert len(load_catalog()) > 50

    def test_is_cached(self) -> None:
        assert load_catalog() is load_catalog()

    def test_expected_frameworks_present(self) -> None:
        ids = {fw.id for fw in load_catalog().frameworks}
        assert {"nist-800-53-r5", "cis-aws", "cis-azure", "cis-k8s"} <= ids

    def test_control_ids_unique_within_framework(self) -> None:
        for fw in load_catalog().frameworks:
            ids = [c.id for c in fw.controls]
            assert len(ids) == len(set(ids)), f"duplicate control in {fw.id}"

    def test_seed_catalogs_are_flagged_non_authoritative(self) -> None:
        for fw in load_catalog().frameworks:
            assert fw.authoritative is False

    def test_every_framework_declares_a_source(self) -> None:
        for fw in load_catalog().frameworks:
            assert fw.source and fw.source.startswith("https://")

    def test_lookup_known_control(self) -> None:
        control = load_catalog().get("nist-800-53-r5:AC-6")
        assert control is not None
        assert control.title == "Least Privilege"

    def test_lookup_unknown_returns_none(self) -> None:
        assert load_catalog().get("nist-800-53-r5:ZZ-99") is None

    def test_lookup_unknown_framework_returns_none(self) -> None:
        assert load_catalog().get("iso-27001:A.5.1") is None

    def test_lookup_malformed_returns_none(self) -> None:
        assert load_catalog().get("no-colon") is None

    def test_framework_accessor(self) -> None:
        assert load_catalog().framework("cis-k8s") is not None
        assert load_catalog().framework("nope") is None

    def test_resolve_skips_unknown(self) -> None:
        resolved = load_catalog().resolve(["nist-800-53-r5:AC-6", "bogus:X"])
        assert len(resolved) == 1

    def test_unknown_reports_only_bad_ids(self) -> None:
        assert load_catalog().unknown(["nist-800-53-r5:AC-6", "bogus:X"]) == ["bogus:X"]

    def test_iteration_yields_every_control(self) -> None:
        catalog = load_catalog()
        assert len(list(catalog)) == len(catalog)


class TestCustomCatalog:
    def test_loads_from_path(self, tmp_path) -> None:
        payload = {
            "frameworks": [
                {
                    "id": "iso-27001",
                    "name": "ISO/IEC 27001",
                    "version": "2022",
                    "controls": [{"id": "A.5.1", "title": "Policies for information security"}],
                }
            ]
        }
        path = tmp_path / "custom.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        catalog = load_catalog(str(path))
        assert isinstance(catalog, ControlCatalog)
        assert catalog.get("iso-27001:A.5.1") is not None

    def test_fixture_control_ids_all_resolve(self, scan_result) -> None:
        catalog = load_catalog()
        for finding in scan_result.findings:
            assert catalog.unknown(finding.control_ids) == []
