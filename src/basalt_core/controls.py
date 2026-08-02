"""Compliance control catalogs and finding-to-control mapping.

Catalogs are **data, not code**. They ship as JSON, carry an explicit framework
version, and can be replaced or extended at runtime without touching the library.
This matters because benchmark revisions renumber controls, and a hard-coded mapping
silently rots.

Control IDs are namespaced ``<framework-id>:<control-id>`` so a finding can carry
mappings from several frameworks at once without collision.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from functools import lru_cache
from importlib import resources
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Control",
    "ControlCatalog",
    "Framework",
    "load_catalog",
    "qualify",
    "split_control_id",
]


class Control(BaseModel):
    """A single control or benchmark recommendation."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, description="Control ID within its framework, e.g. 'AC-6'")
    title: str = Field(min_length=1)
    family: str | None = Field(default=None, description="Control family or benchmark section")
    description: str | None = None


class Framework(BaseModel):
    """A versioned set of controls."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, description="Short framework key, e.g. 'nist-800-53-r5'")
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    source: str | None = Field(default=None, description="Authoritative publication URL")
    authoritative: bool = Field(
        default=False,
        description="False when the shipped set is a seed subset rather than the full catalog",
    )
    controls: list[Control] = Field(default_factory=list)


class ControlCatalog(BaseModel):
    """An indexed collection of frameworks."""

    frameworks: list[Framework] = Field(default_factory=list)

    def framework(self, framework_id: str) -> Framework | None:
        return next((f for f in self.frameworks if f.id == framework_id), None)

    def get(self, qualified_id: str) -> Control | None:
        """Look up a control by its ``framework:control`` identifier."""
        try:
            fw_id, control_id = split_control_id(qualified_id)
        except ValueError:
            return None
        fw = self.framework(fw_id)
        if fw is None:
            return None
        return next((c for c in fw.controls if c.id == control_id), None)

    def resolve(self, qualified_ids: Iterable[str]) -> list[Control]:
        """Resolve many IDs, silently skipping unknown ones."""
        out: list[Control] = []
        for qid in qualified_ids:
            control = self.get(qid)
            if control is not None:
                out.append(control)
        return out

    def unknown(self, qualified_ids: Iterable[str]) -> list[str]:
        """IDs that do not resolve. Used by CI to catch typos in scanner rule metadata."""
        return [qid for qid in qualified_ids if self.get(qid) is None]

    def __iter__(self) -> Iterator[Control]:  # type: ignore[override]
        for fw in self.frameworks:
            yield from fw.controls

    def __len__(self) -> int:
        return sum(len(fw.controls) for fw in self.frameworks)


def split_control_id(qualified_id: str) -> tuple[str, str]:
    """Split ``'nist-800-53-r5:AC-6'`` into ``('nist-800-53-r5', 'AC-6')``."""
    if ":" not in qualified_id:
        raise ValueError(f"control id must be 'framework:control', got {qualified_id!r}")
    fw_id, _, control_id = qualified_id.partition(":")
    if not fw_id or not control_id:
        raise ValueError(f"control id must be 'framework:control', got {qualified_id!r}")
    return fw_id, control_id


def qualify(framework_id: str, control_id: str) -> str:
    """Build a namespaced control ID."""
    return f"{framework_id}:{control_id}"


@lru_cache(maxsize=1)
def _builtin_catalog() -> ControlCatalog:
    raw = resources.files("basalt_core.data").joinpath("controls.json").read_text(encoding="utf-8")
    return ControlCatalog.model_validate(json.loads(raw))


def load_catalog(path: str | None = None) -> ControlCatalog:
    """Load the built-in seed catalog, or a custom catalog from ``path``.

    The built-in catalog is cached; a custom catalog is read fresh each call.
    """
    if path is None:
        return _builtin_catalog()
    raw = Path(path).read_text(encoding="utf-8")
    return ControlCatalog.model_validate(json.loads(raw))
