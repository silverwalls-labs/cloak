"""Config dict → TOML serialization.

Hand-rolled for the cloak config surface (two sections, no arrays,
no nested tables beyond ``[rules.<id>]``). Zero dependencies — the
stdlib ``tomllib`` is read-only. Mirrors ``adapters/node/src/config.ts``;
keys are snake_case and map 1:1 to the TOML keys.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
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


# Raw control characters are invalid in TOML basic strings (only tab
# may appear unescaped); emit the remaining C0 range and DEL as
# \uXXXX escapes instead of producing a TOML string the Rust parser
# rejects with a confusing "invalid config" error.
_TOML_SIMPLE_ESCAPES: dict[str, str] = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _toml_string(value: str) -> str:
    """Escape a TOML basic string value."""
    parts = ['"']
    for ch in value:
        escaped = _TOML_SIMPLE_ESCAPES.get(ch)
        if escaped is not None:
            parts.append(escaped)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            parts.append(f"\\u{ord(ch):04x}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


# Cloak rule IDs are kebab-case identifiers from a fixed catalog
# (e.g. `github-token`, `phone-intl`). A rule ID containing TOML-
# special characters (`.`, `]`, `"`, whitespace) would produce an
# invalid or misinterpreted section header — reject early with a
# clear message instead of forwarding a broken TOML string to the
# Rust parser.
_VALID_RULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _validate_rule_id(rule_id: str) -> None:
    """Reject rule IDs that would produce a broken TOML section header."""
    if not isinstance(rule_id, str):
        # str.format would emit a section header like "[rules.123]" —
        # rejected by the kebab-case check anyway, but with an
        # unreadable re error; fail with the actual type instead.
        raise TypeError(
            f"invalid rule ID {rule_id!r}: must be a kebab-case str "
            '(e.g. "github-token", "phone-intl")'
        )
    # fullmatch, not match: `$` in a `re.match` pattern also matches just
    # before a trailing "\n", so "github-token\n" would otherwise slip
    # through and emit a broken `[rules.github-token\n]` header (and
    # diverge from the Node adapter, whose `.test()` rejects it).
    if not _VALID_RULE_ID.fullmatch(rule_id):
        raise ValueError(
            f'invalid rule ID "{rule_id}": must be kebab-case '
            '(e.g. "github-token", "phone-intl")'
        )


def _validate_section(section: object, name: str) -> dict[str, object]:
    """Runtime-validate a config section value.

    ``config_to_toml`` is the boundary between untyped caller dicts
    (JSON round-trips, kwargs) and the TOML handed to the Rust parser —
    reject wrong types here with a clear message instead of letting them
    produce broken or misinterpreted TOML.
    """
    if not isinstance(section, Mapping):
        raise TypeError(f"{name} must be a mapping, got {type(section).__name__}")
    return dict(section)


def config_to_toml(config: CloakConfig) -> str:
    """Serialize a :class:`CloakConfig` to a TOML string."""
    lines: list[str] = []

    # `in`-based presence, not `.get() is not None`: an explicit ``None``
    # value must be a TypeError, not silently "unset" (a JSON config
    # with ``"enabled": null`` would otherwise quietly enable the rule).
    if "redaction" in config:
        redaction = _validate_section(config["redaction"], "redaction")
        lines.append("[redaction]")
        if "digest_key" in redaction:
            digest_key: object = redaction["digest_key"]
            if not isinstance(digest_key, str):
                raise TypeError(
                    "redaction.digest_key must be a str, "
                    f"got {type(digest_key).__name__}"
                )
            lines.append(f"digest_key = {_toml_string(digest_key)}")
        lines.append("")

    if "rules" in config:
        rules = _validate_section(config["rules"], "rules")
        for rule_id, rule_config in rules.items():
            _validate_rule_id(rule_id)
            lines.append(f"[rules.{rule_id}]")
            rule = _validate_section(rule_config, f"rules.{rule_id}")
            if "enabled" in rule:
                enabled: object = rule["enabled"]
                # Reject non-bools instead of silently mis-serializing:
                # str(bool) would emit "True", and a truthy string like
                # "no" would otherwise round-trip to enabled = false.
                if not isinstance(enabled, bool):
                    raise TypeError(
                        f"rules.{rule_id}.enabled must be a bool, "
                        f"got {type(enabled).__name__}"
                    )
                lines.append(f"enabled = {'true' if enabled else 'false'}")
            lines.append("")

    return "\n".join(lines)
