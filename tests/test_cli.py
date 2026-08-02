from __future__ import annotations

import json

import pytest

from basalt_core import ScanResult
from basalt_core.cli import main


@pytest.fixture
def result_file(tmp_path, scan_result: ScanResult):
    path = tmp_path / "scan.json"
    path.write_text(scan_result.model_dump_json(), encoding="utf-8")
    return str(path)


class TestValidate:
    def test_valid_document_exits_zero(self, result_file: str, capsys) -> None:
        assert main(["validate", result_file]) == 0
        out = capsys.readouterr().out
        assert "valid: 3 findings" in out
        assert "max risk: 90" in out

    def test_malformed_document_exits_one(self, tmp_path, capsys) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{ not json", encoding="utf-8")
        assert main(["validate", str(path)]) == 1
        assert "invalid:" in capsys.readouterr().err

    def test_unknown_controls_warn_but_pass(
        self, tmp_path, scan_result: ScanResult, capsys
    ) -> None:
        mutated = scan_result.model_copy(
            update={
                "findings": [
                    scan_result.findings[0].model_copy(update={"control_ids": ["fake:X-1"]})
                ]
            }
        )
        path = tmp_path / "scan.json"
        path.write_text(mutated.model_dump_json(), encoding="utf-8")
        assert main(["validate", str(path)]) == 0
        assert "unknown control ids" in capsys.readouterr().err

    def test_strict_fails_on_unknown_controls(self, tmp_path, scan_result: ScanResult) -> None:
        mutated = scan_result.model_copy(
            update={
                "findings": [
                    scan_result.findings[0].model_copy(update={"control_ids": ["fake:X-1"]})
                ]
            }
        )
        path = tmp_path / "scan.json"
        path.write_text(mutated.model_dump_json(), encoding="utf-8")
        assert main(["validate", str(path), "--strict"]) == 1

    def test_reads_stdin(self, scan_result: ScanResult, monkeypatch, capsys) -> None:
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO(scan_result.model_dump_json()))
        assert main(["validate", "-"]) == 0
        assert "valid: 3 findings" in capsys.readouterr().out


class TestConvert:
    @pytest.mark.parametrize("fmt", ["sarif", "ocsf", "basalt"])
    def test_emits_valid_json(self, result_file: str, fmt: str, capsys) -> None:
        assert main(["convert", result_file, "--to", fmt]) == 0
        json.loads(capsys.readouterr().out)

    def test_jsonl_emits_one_object_per_line(self, result_file: str, capsys) -> None:
        main(["convert", result_file, "--to", "jsonl"])
        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert len(lines) == 3

    def test_writes_output_file(self, result_file: str, tmp_path) -> None:
        out = tmp_path / "out.sarif"
        assert main(["convert", result_file, "--to", "sarif", "-o", str(out)]) == 0
        assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"

    def test_dedupe_flag(self, tmp_path, scan_result: ScanResult, capsys) -> None:
        doubled = scan_result.model_copy(
            update={"findings": [*scan_result.findings, scan_result.findings[0]]}
        )
        path = tmp_path / "dup.json"
        path.write_text(doubled.model_dump_json(), encoding="utf-8")
        main(["convert", str(path), "--to", "jsonl", "--dedupe"])
        assert len(capsys.readouterr().out.strip().splitlines()) == 3

    def test_compact_output_is_single_line(self, result_file: str, capsys) -> None:
        main(["convert", result_file, "--to", "sarif", "--compact"])
        assert len(capsys.readouterr().out.strip().splitlines()) == 1

    def test_rejects_unknown_format(self, result_file: str) -> None:
        with pytest.raises(SystemExit):
            main(["convert", result_file, "--to", "xml"])


class TestControls:
    def test_lists_all_frameworks(self, capsys) -> None:
        assert main(["controls"]) == 0
        out = capsys.readouterr().out
        assert "nist-800-53-r5" in out
        assert "cis-k8s" in out
        assert "seed subset" in out

    def test_filters_by_framework(self, capsys) -> None:
        main(["controls", "--framework", "cis-k8s"])
        out = capsys.readouterr().out
        assert "cis-k8s" in out
        assert "nist-800-53-r5  NIST" not in out

    def test_json_output(self, capsys) -> None:
        main(["controls", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["frameworks"]) == 4


class TestMisc:
    def test_scanners_reports_none_installed(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr("basalt_core.cli.discover_scanners", dict)
        assert main(["scanners"]) == 0
        assert "no scanners installed" in capsys.readouterr().out

    def test_scanners_lists_installed(self, capsys, monkeypatch) -> None:
        from tests.test_plugin import DemoScanner

        monkeypatch.setattr("basalt_core.cli.discover_scanners", lambda: {"demo": DemoScanner})
        main(["scanners"])
        assert "basalt-demo" not in capsys.readouterr().out.split("\n")[0].split()[0]

    def test_schema_is_valid_json_schema(self, capsys) -> None:
        assert main(["schema"]) == 0
        schema = json.loads(capsys.readouterr().out)
        assert "$defs" in schema
        assert schema["title"] == "ScanResult"

    def test_no_command_exits(self) -> None:
        with pytest.raises(SystemExit):
            main([])
