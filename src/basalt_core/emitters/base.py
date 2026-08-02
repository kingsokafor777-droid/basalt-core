"""Emitter protocol.

An emitter is a pure transform from :class:`~basalt_core.models.ScanResult` to a
serializable document. Emitters never perform I/O; callers decide where bytes go.
"""

from __future__ import annotations

import abc
import json
from typing import Any

from ..models import ScanResult

__all__ = ["EMITTERS", "Emitter", "available_formats", "get_emitter", "register_emitter"]


class Emitter(abc.ABC):
    """Base class for output formats."""

    #: Short format key used by the CLI (``--to sarif``).
    format: str = "generic"
    #: Conventional file extension, without the dot.
    extension: str = "json"
    #: MIME type for HTTP consumers.
    media_type: str = "application/json"

    @abc.abstractmethod
    def emit(self, result: ScanResult) -> Any:
        """Return the document as plain Python data structures."""

    def emit_json(self, result: ScanResult, indent: int | None = 2) -> str:
        """Serialize :meth:`emit` to JSON with stable key ordering."""
        return json.dumps(self.emit(result), indent=indent, sort_keys=False, default=str)


EMITTERS: dict[str, type[Emitter]] = {}


def register_emitter(cls: type[Emitter]) -> type[Emitter]:
    """Class decorator that adds an emitter to the registry."""
    EMITTERS[cls.format] = cls
    return cls


def get_emitter(format: str) -> Emitter:
    """Instantiate a registered emitter by format key."""
    key = format.strip().lower()
    if key not in EMITTERS:
        raise KeyError(f"unknown format {format!r} (available: {', '.join(sorted(EMITTERS))})")
    return EMITTERS[key]()


def available_formats() -> list[str]:
    return sorted(EMITTERS)
