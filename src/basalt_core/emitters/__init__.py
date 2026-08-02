"""Output formats for scan results.

Importing this package registers every built-in emitter.
"""

from .base import EMITTERS, Emitter, available_formats, get_emitter, register_emitter
from .native import JsonLinesEmitter, NativeEmitter
from .ocsf import OcsfEmitter
from .sarif import SarifEmitter

__all__ = [
    "EMITTERS",
    "Emitter",
    "JsonLinesEmitter",
    "NativeEmitter",
    "OcsfEmitter",
    "SarifEmitter",
    "available_formats",
    "get_emitter",
    "register_emitter",
]
