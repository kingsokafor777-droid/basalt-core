"""Compatibility shims.

Kept deliberately small. Anything here should be deletable the moment the supported
Python floor moves past the version that needs it.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["StrEnum"]


class StrEnum(str, Enum):
    """A string enum with sane rendering, available on Python 3.10.

    ``enum.StrEnum`` landed in 3.11. Plain ``(str, Enum)`` is available earlier but
    renders as ``Severity.HIGH`` in f-strings and ``str()``, which silently corrupts log
    lines and any code path that formats a member instead of reading ``.value``. Defining
    ``__str__`` restores the 3.11 behaviour.

    Remove this class and import from ``enum`` directly once the floor reaches 3.11.
    """

    def __str__(self) -> str:
        return str(self.value)

    def __format__(self, format_spec: str) -> str:
        return str.__format__(str(self.value), format_spec)
