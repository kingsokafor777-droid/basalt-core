"""Severity taxonomy and the deterministic risk model.

Design rule: risk scoring is a pure function with no hidden state and no ML. The same
finding always produces the same score, and the score always ships with the factors
that produced it so a dashboard can answer "why is this a 72?" without re-deriving it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ._compat import StrEnum

__all__ = [
    "Exploitability",
    "Exposure",
    "RiskScore",
    "Severity",
    "score_risk",
]


class Severity(StrEnum):
    """Impact if the finding is true and reachable.

    Ordinals are stable and are relied on by the SARIF and OCSF emitters.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @classmethod
    def from_any(cls, value: str | int | Severity) -> Severity:
        """Coerce common upstream spellings (CVSS words, numeric ranks) into the enum."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            for member, rank in _RANKS.items():
                if rank == value:
                    return member
            raise ValueError(f"no severity with rank {value}")
        key = value.strip().lower()
        aliases = {
            "informational": cls.INFO,
            "none": cls.INFO,
            "note": cls.INFO,
            "warning": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "error": cls.HIGH,
            "important": cls.HIGH,
            "severe": cls.CRITICAL,
            "fatal": cls.CRITICAL,
        }
        if key in aliases:
            return aliases[key]
        return cls(key)


_RANKS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_BASE_SCORE: dict[Severity, int] = {
    Severity.INFO: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}


class Exposure(StrEnum):
    """Network reachability of the affected resource."""

    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    ISOLATED = "isolated"


_EXPOSURE_FACTOR: dict[Exposure, float] = {
    Exposure.PUBLIC: 1.00,
    Exposure.EXTERNAL: 0.90,
    Exposure.INTERNAL: 0.75,
    Exposure.ISOLATED: 0.55,
}


class Exploitability(StrEnum):
    """Effort required to turn the misconfiguration into an incident."""

    TRIVIAL = "trivial"
    MODERATE = "moderate"
    DIFFICULT = "difficult"
    THEORETICAL = "theoretical"


_EXPLOITABILITY_FACTOR: dict[Exploitability, float] = {
    Exploitability.TRIVIAL: 1.00,
    Exploitability.MODERATE: 0.85,
    Exploitability.DIFFICULT: 0.65,
    Exploitability.THEORETICAL: 0.40,
}


class RiskScore(BaseModel):
    """A score plus the factors that produced it."""

    model_config = ConfigDict(frozen=True)

    value: int = Field(ge=0, le=100)
    base: int
    exposure_factor: float
    exploitability_factor: float
    severity: Severity
    exposure: Exposure
    exploitability: Exploitability

    @property
    def band(self) -> str:
        """Coarse bucket for dashboard grouping."""
        if self.value >= 80:
            return "critical"
        if self.value >= 60:
            return "high"
        if self.value >= 35:
            return "medium"
        if self.value >= 15:
            return "low"
        return "informational"

    def explain(self) -> str:
        return (
            f"{self.base} (severity={self.severity.value}) "
            f"x {self.exposure_factor:.2f} (exposure={self.exposure.value}) "
            f"x {self.exploitability_factor:.2f} (exploitability={self.exploitability.value}) "
            f"= {self.value}"
        )


def score_risk(
    severity: Severity,
    exposure: Exposure = Exposure.INTERNAL,
    exploitability: Exploitability = Exploitability.MODERATE,
) -> RiskScore:
    """Compute the risk score.

    ``base(severity) x exposure_factor x exploitability_factor``, rounded half-up and
    clamped to ``[0, 100]``. Multiplicative rather than additive so that an isolated,
    theoretically-exploitable critical never outranks a trivially-exploitable public
    high, which is the ordering an on-call engineer actually wants.
    """
    base = _BASE_SCORE[severity]
    ef = _EXPOSURE_FACTOR[exposure]
    xf = _EXPLOITABILITY_FACTOR[exploitability]
    raw = base * ef * xf
    value = int(min(100, max(0, int(raw + 0.5))))
    return RiskScore(
        value=value,
        base=base,
        exposure_factor=ef,
        exploitability_factor=xf,
        severity=severity,
        exposure=exposure,
        exploitability=exploitability,
    )
