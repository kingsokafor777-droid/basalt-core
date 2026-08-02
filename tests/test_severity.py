from __future__ import annotations

import pytest

from basalt_core.severity import Exploitability, Exposure, Severity, score_risk


class TestSeverity:
    def test_ranks_are_ordered(self) -> None:
        ranks = [
            s.rank
            for s in [
                Severity.INFO,
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            ]
        ]
        assert ranks == sorted(ranks)
        assert len(set(ranks)) == 5

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("CRITICAL", Severity.CRITICAL),
            ("  high  ", Severity.HIGH),
            ("informational", Severity.INFO),
            ("warning", Severity.MEDIUM),
            ("error", Severity.HIGH),
            ("fatal", Severity.CRITICAL),
            ("moderate", Severity.MEDIUM),
        ],
    )
    def test_from_any_string(self, raw: str, expected: Severity) -> None:
        assert Severity.from_any(raw) is expected

    def test_from_any_int(self) -> None:
        assert Severity.from_any(4) is Severity.CRITICAL

    def test_from_any_passthrough(self) -> None:
        assert Severity.from_any(Severity.LOW) is Severity.LOW

    def test_from_any_rejects_unknown(self) -> None:
        with pytest.raises(ValueError):
            Severity.from_any("catastrophic")

    def test_from_any_rejects_bad_rank(self) -> None:
        with pytest.raises(ValueError, match="no severity with rank"):
            Severity.from_any(99)


class TestRiskScore:
    def test_worst_case_is_ninety(self) -> None:
        score = score_risk(Severity.CRITICAL, Exposure.PUBLIC, Exploitability.TRIVIAL)
        assert score.value == 90
        assert score.band == "critical"

    def test_best_case_is_near_zero(self) -> None:
        score = score_risk(Severity.INFO, Exposure.ISOLATED, Exploitability.THEORETICAL)
        assert score.value == 1
        assert score.band == "informational"

    def test_is_deterministic(self) -> None:
        a = score_risk(Severity.HIGH, Exposure.EXTERNAL, Exploitability.MODERATE)
        b = score_risk(Severity.HIGH, Exposure.EXTERNAL, Exploitability.MODERATE)
        assert a == b

    def test_stays_within_bounds(self) -> None:
        for sev in Severity:
            for exp in Exposure:
                for xpl in Exploitability:
                    assert 0 <= score_risk(sev, exp, xpl).value <= 100

    def test_exposure_is_monotonic(self) -> None:
        order = [Exposure.ISOLATED, Exposure.INTERNAL, Exposure.EXTERNAL, Exposure.PUBLIC]
        values = [score_risk(Severity.HIGH, e).value for e in order]
        assert values == sorted(values)

    def test_exploitability_is_monotonic(self) -> None:
        order = [
            Exploitability.THEORETICAL,
            Exploitability.DIFFICULT,
            Exploitability.MODERATE,
            Exploitability.TRIVIAL,
        ]
        values = [score_risk(Severity.HIGH, Exposure.PUBLIC, x).value for x in order]
        assert values == sorted(values)

    def test_public_trivial_high_beats_isolated_theoretical_critical(self) -> None:
        reachable = score_risk(Severity.HIGH, Exposure.PUBLIC, Exploitability.TRIVIAL)
        buried = score_risk(Severity.CRITICAL, Exposure.ISOLATED, Exploitability.THEORETICAL)
        assert reachable.value > buried.value

    def test_defaults_are_internal_moderate(self) -> None:
        assert (
            score_risk(Severity.MEDIUM).value
            == score_risk(Severity.MEDIUM, Exposure.INTERNAL, Exploitability.MODERATE).value
        )

    @pytest.mark.parametrize(
        ("value", "band"),
        [
            (95, "critical"),
            (80, "critical"),
            (60, "high"),
            (35, "medium"),
            (15, "low"),
            (5, "informational"),
        ],
    )
    def test_bands(self, value: int, band: str) -> None:
        from basalt_core.severity import RiskScore

        score = RiskScore(
            value=value,
            base=value,
            exposure_factor=1.0,
            exploitability_factor=1.0,
            severity=Severity.HIGH,
            exposure=Exposure.PUBLIC,
            exploitability=Exploitability.TRIVIAL,
        )
        assert score.band == band

    def test_explain_shows_all_factors(self) -> None:
        text = score_risk(Severity.HIGH, Exposure.PUBLIC, Exploitability.TRIVIAL).explain()
        assert "severity=high" in text
        assert "exposure=public" in text
        assert "exploitability=trivial" in text
        assert text.endswith("= 70")

    def test_score_is_frozen(self) -> None:
        from pydantic import ValidationError

        score = score_risk(Severity.LOW)
        with pytest.raises(ValidationError):
            score.value = 99  # type: ignore[misc]


class TestStrEnumCompat:
    """Locks the rendering behaviour the 3.10 compat shim exists to preserve.

    Without an explicit ``__str__``, ``(str, Enum)`` renders as ``Severity.HIGH``, which
    silently corrupts log lines and any consumer that formats a member rather than
    reading ``.value``.
    """

    def test_str_returns_the_value(self) -> None:
        assert str(Severity.HIGH) == "high"
        assert str(Exposure.PUBLIC) == "public"
        assert str(Exploitability.TRIVIAL) == "trivial"

    def test_fstring_returns_the_value(self) -> None:
        assert f"{Severity.CRITICAL}" == "critical"

    def test_format_spec_is_honoured(self) -> None:
        assert f"{Severity.LOW:>8}" == "     low"

    def test_still_a_string_instance(self) -> None:
        assert isinstance(Severity.MEDIUM, str)
        assert Severity.MEDIUM == "medium"

    def test_json_serializable_without_encoder(self) -> None:
        import json

        assert json.dumps({"severity": Severity.HIGH}) == '{"severity": "high"}'
