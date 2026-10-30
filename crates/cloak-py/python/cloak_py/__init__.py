"""Native Python binding for cloak — guarantee-grade secrets redaction.

The pyo3 flavor of the cloak embedding surface: same conceptual API as
every cloak binding (see ``docs/06-embedding.md``) — ``create_engine``
→ ``session`` → ``push``/``finish``, plus the one-shot ``redact``
convenience — but binding ``cloak-core`` directly instead of going
through the WASM artifact (``cloak_python``). The GIL is released
during scans.
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
