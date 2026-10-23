"""Config dict → TOML serialization.

Hand-rolled for the cloak config surface (two sections, no arrays,
no nested tables beyond ``[rules.<id>]``). Zero dependencies — the
stdlib ``tomllib`` is read-only. Mirrors ``adapters/node/src/config.ts``;
keys are snake_case and map 1:1 to the TOML keys.
"""

from __future__ import annotations

import re
from typing import TypedDict

__all__ = ["CloakConfig", "RedactionConfig", "RuleConfig", "config_to_toml"]


class RuleConfig(TypedDict, total=False):
    """Per-rule configuration (mirrors ``[rules.<id>]`` in TOML)."""

    enabled: bool


class RedactionConfig(TypedDict, total=False):
    """Redaction section (mirrors ``[redaction]`` in TOML)."""

    digest_key: str
    """Digest key source — typically ``"env:CLOAK_DIGEST_KEY"``."""


class CloakConfig(TypedDict, total=False):
    """Cloak engine configuration.

    Serialized to TOML before passing to the WASM module. Rule IDs are
    kebab-case strings matching the cloak catalog (``"github-token"``,
    ``"phone-intl"``, etc.).
    """

    redaction: RedactionConfig
    rules: dict[str, RuleConfig]


def _toml_string(value: str) -> str:
    """Escape a TOML basic string value."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


# Cloak rule IDs are kebab-case identifiers from a fixed catalog
# (e.g. `github-token`, `phone-intl`). A rule ID containing TOML-
# special characters (`.`, `]`, `"`, whitespace) would produce an
# invalid or misinterpreted section header — reject early with a
# clear message instead of forwarding a broken TOML string to the
# Rust parser.
_VALID_RULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _validate_rule_id(rule_id: str) -> None:
    """Reject rule IDs that would produce a broken TOML section header."""
    # fullmatch, not match: `$` in a `re.match` pattern also matches just
    # before a trailing "\n", so "github-token\n" would otherwise slip
    # through and emit a broken `[rules.github-token\n]` header (and
    # diverge from the Node adapter, whose `.test()` rejects it).
    if not _VALID_RULE_ID.fullmatch(rule_id):
        raise ValueError(
            f'invalid rule ID "{rule_id}": must be kebab-case '
            '(e.g. "github-token", "phone-intl")'
        )


def config_to_toml(config: CloakConfig) -> str:
    """Serialize a :class:`CloakConfig` to a TOML string."""
    lines: list[str] = []

    redaction = config.get("redaction")
    if redaction is not None:
        lines.append("[redaction]")
        digest_key = redaction.get("digest_key")
        if digest_key is not None:
            lines.append(f"digest_key = {_toml_string(digest_key)}")
        lines.append("")

    rules = config.get("rules")
    if rules is not None:
        for rule_id, rule_config in rules.items():
            _validate_rule_id(rule_id)
            lines.append(f"[rules.{rule_id}]")
            enabled = rule_config.get("enabled")
            if enabled is not None:
                # TOML booleans are lowercase — str(bool) would emit "True".
                lines.append(f"enabled = {'true' if enabled else 'false'}")
            lines.append("")

    return "\n".join(lines)
