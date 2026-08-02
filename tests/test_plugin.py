from __future__ import annotations

from collections.abc import Iterable

import pytest

from basalt_core import (
    Finding,
    Provider,
    ResourceRef,
    ScanContext,
    Scanner,
    ScannerError,
    Severity,
    load_scanner,
)
from basalt_core.plugin import ENTRY_POINT_GROUP, discover_scanners


def _finding(rule_id: str, resource: ResourceRef) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        description="d",
        severity=Severity.MEDIUM,
        resource=resource,
        scanner="placeholder",
    )


class DemoScanner(Scanner):
    name = "basalt-demo"
    version = "9.9.9"
    provider = Provider.AWS
    description = "test double"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        resource = ResourceRef(provider=Provider.AWS, resource_type="T", uid="u1")
        for rule_id in ("demo.one", "demo.two"):
            if context.selects(rule_id):
                yield _finding(rule_id, resource)


class ExplodingScanner(Scanner):
    name = "basalt-boom"
    provider = Provider.GENERIC

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        raise RuntimeError("credentials expired")
        yield  # pragma: no cover


class TestScanContext:
    def test_empty_filter_selects_everything(self) -> None:
        assert ScanContext().selects("anything")

    def test_filter_restricts(self) -> None:
        ctx = ScanContext(rule_filter=["demo.one"])
        assert ctx.selects("demo.one")
        assert not ctx.selects("demo.two")

    def test_credentials_excluded_from_dump(self) -> None:
        ctx = ScanContext(credentials={"secret": "value"})
        assert "credentials" not in ctx.model_dump()


class TestScannerRun:
    def test_produces_scan_result(self) -> None:
        result = DemoScanner().run()
        assert len(result.findings) == 2
        assert result.metadata.checks_run == 2

    def test_stamps_scanner_identity_on_findings(self) -> None:
        for finding in DemoScanner().run().findings:
            assert finding.scanner == "basalt-demo"
            assert finding.scanner_version == "9.9.9"

    def test_metadata_carries_context(self) -> None:
        ctx = ScanContext(account="123456789012", regions=["ca-central-1"])
        meta = DemoScanner().run(ctx).metadata
        assert meta.account == "123456789012"
        assert meta.regions == ["ca-central-1"]

    def test_rule_filter_applied(self) -> None:
        result = DemoScanner().run(ScanContext(rule_filter=["demo.two"]))
        assert [f.rule_id for f in result.findings] == ["demo.two"]

    def test_completed_at_always_set(self) -> None:
        assert DemoScanner().run().metadata.completed_at is not None

    def test_duration_is_non_negative(self) -> None:
        duration = DemoScanner().run().metadata.duration_seconds
        assert duration is not None and duration >= 0

    def test_exception_captured_not_raised(self) -> None:
        result = ExplodingScanner().run()
        assert result.findings == []
        assert result.metadata.errors == ["RuntimeError: credentials expired"]

    def test_scanner_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[abstract]


class TestDiscovery:
    def test_group_name_is_stable(self) -> None:
        assert ENTRY_POINT_GROUP == "basalt.scanners"

    def test_discovery_returns_mapping(self) -> None:
        assert isinstance(discover_scanners(), dict)

    def test_load_missing_scanner_raises(self) -> None:
        with pytest.raises(ScannerError, match="no scanner named"):
            load_scanner("basalt-does-not-exist")

    def test_broken_entry_point_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class BadEntryPoint:
            name = "bad"

            def load(self):
                raise ImportError("missing dependency")

        class GoodEntryPoint:
            name = "demo"

            def load(self):
                return DemoScanner

        monkeypatch.setattr(
            "basalt_core.plugin.entry_points", lambda group: [BadEntryPoint(), GoodEntryPoint()]
        )
        found = discover_scanners()
        assert found == {"demo": DemoScanner}

    def test_non_scanner_entry_point_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class NotAScanner:
            name = "nope"

            def load(self):
                return dict

        monkeypatch.setattr("basalt_core.plugin.entry_points", lambda group: [NotAScanner()])
        assert discover_scanners() == {}
