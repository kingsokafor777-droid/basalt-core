"""The contract every Basalt scanner implements.

Scanners are discovered through the ``basalt.scanners`` entry-point group, so
``basalt-aws``, ``basalt-azure``, ``basalt-iac`` and ``basalt-k8s`` become available
simply by being installed. Nothing in this package imports them.

A scanner implementation looks like::

    class S3PublicAccess(Scanner):
        name = "basalt-aws"
        version = "0.1.0"
        provider = Provider.AWS

        def scan(self, context: ScanContext) -> Iterable[Finding]:
            ...

and registers itself in ``pyproject.toml``::

    [project.entry-points."basalt.scanners"]
    aws = "basalt_aws.scanner:S3PublicAccess"
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from importlib.metadata import entry_points
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import Finding, Provider, ScanMetadata, ScanResult, utc_now

__all__ = [
    "ENTRY_POINT_GROUP",
    "ScanContext",
    "Scanner",
    "ScannerError",
    "discover_scanners",
    "load_scanner",
]

ENTRY_POINT_GROUP = "basalt.scanners"


class ScannerError(RuntimeError):
    """Raised when a scanner cannot run at all, as opposed to finding nothing."""


class ScanContext(BaseModel):
    """Everything a scanner needs, supplied by the caller rather than read from env.

    Keeping credentials and targeting explicit makes scanners trivially testable and
    keeps a scan reproducible from its recorded context.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    account: str | None = Field(default=None, description="Account, subscription or project")
    regions: list[str] = Field(default_factory=list)
    paths: list[str] = Field(
        default_factory=list, description="Filesystem targets for static analysis"
    )
    rule_filter: list[str] = Field(
        default_factory=list, description="If set, only these rule_ids run"
    )
    tags: dict[str, str] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict, description="Scanner-specific settings")
    credentials: Any = Field(default=None, exclude=True, repr=False)

    def selects(self, rule_id: str) -> bool:
        """Whether a rule should run under the current filter."""
        return not self.rule_filter or rule_id in self.rule_filter


class Scanner(abc.ABC):
    """Base class for all scanners.

    Subclasses implement :meth:`scan` and return findings lazily. :meth:`run` wraps
    that in metadata, timing and error capture, and is what callers should invoke.
    """

    #: Distribution name, mirrored onto every emitted finding.
    name: str = "basalt-scanner"
    #: Scanner version, mirrored onto every emitted finding.
    version: str = "0.0.0"
    #: Provider this scanner targets.
    provider: Provider = Provider.GENERIC
    #: Human-readable one-liner used by the CLI listing.
    description: str = ""

    @abc.abstractmethod
    def scan(self, context: ScanContext) -> Iterable[Finding]:
        """Yield findings. Implementations should not raise for individual check failures."""

    def run(self, context: ScanContext | None = None) -> ScanResult:
        """Execute :meth:`scan` and package the output as a :class:`ScanResult`."""
        context = context or ScanContext()
        metadata = ScanMetadata(
            scanner=self.name,
            scanner_version=self.version,
            provider=self.provider,
            account=context.account,
            regions=list(context.regions),
            started_at=utc_now(),
        )
        findings: list[Finding] = []
        try:
            for finding in self.scan(context):
                findings.append(
                    finding.model_copy(
                        update={"scanner": self.name, "scanner_version": self.version}
                    )
                )
        except Exception as exc:
            metadata.errors.append(f"{type(exc).__name__}: {exc}")
        metadata.completed_at = utc_now()
        metadata.checks_run = len(findings)
        return ScanResult(metadata=metadata, findings=findings)


def discover_scanners() -> dict[str, type[Scanner]]:
    """Return every installed scanner keyed by entry-point name.

    Entry points that fail to import are skipped rather than raising, so one broken
    plugin cannot take down the whole toolchain.
    """
    found: dict[str, type[Scanner]] = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = ep.load()
        except Exception:
            continue
        if isinstance(obj, type) and issubclass(obj, Scanner):
            found[ep.name] = obj
    return found


def load_scanner(name: str) -> type[Scanner]:
    """Load one scanner by entry-point name, raising if it is not installed."""
    scanners = discover_scanners()
    if name not in scanners:
        available = ", ".join(sorted(scanners)) or "none installed"
        raise ScannerError(f"no scanner named {name!r} (available: {available})")
    return scanners[name]
