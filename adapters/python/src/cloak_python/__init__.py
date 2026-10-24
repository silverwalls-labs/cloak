"""Python adapter for cloak — guarantee-grade secrets redaction via WASM.

Thin glue over the shared ``cloak_wasm.wasm`` artifact through
wasmtime-py. Same conceptual API as every cloak binding (see
``docs/06-embedding.md``): ``create_engine`` → ``session`` →
``push``/``finish``, plus the one-shot ``redact`` convenience.
"""

from .config import CloakConfig, RedactionConfig, RuleConfig, config_to_toml
from .engine import (
    CloakEngine,
    CloakError,
    CloakSession,
    CloakStats,
    RedactResult,
    create_engine,
)
from .handlers import CloakHandler
from .writer import CloakWriter

__version__ = "0.1.0"

__all__ = [
    "CloakConfig",
    "CloakEngine",
    "CloakError",
    "CloakHandler",
    "CloakSession",
    "CloakStats",
    "CloakWriter",
    "RedactResult",
    "RedactionConfig",
    "RuleConfig",
    "config_to_toml",
    "create_engine",
]
