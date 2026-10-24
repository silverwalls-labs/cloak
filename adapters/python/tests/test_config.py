"""Config serialization tests: dict → TOML → engine accepts it.

Mirrors ``adapters/node/test/config.test.ts``.
"""

from __future__ import annotations

import pytest

from cloak_python import config_to_toml, create_engine

# ── Unit: config_to_toml ───────────────────────────────────────────


def test_serializes_redaction_section() -> None:
    toml = config_to_toml({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})
    assert "[redaction]" in toml
    assert 'digest_key = "env:CLOAK_DIGEST_KEY"' in toml


def test_serializes_rule_overrides() -> None:
    toml = config_to_toml({"rules": {"phone-intl": {"enabled": False}}})
    assert "[rules.phone-intl]" in toml
    assert "enabled = false" in toml


def test_serializes_full_config() -> None:
    toml = config_to_toml(
        {
            "redaction": {"digest_key": "env:MY_KEY"},
            "rules": {
                "phone-intl": {"enabled": False},
                "credit-card": {"enabled": True},
            },
        }
    )
    assert '[redaction]\ndigest_key = "env:MY_KEY"' in toml
    assert "[rules.phone-intl]\nenabled = false" in toml
    assert "[rules.credit-card]\nenabled = true" in toml


def test_empty_config_serializes_to_empty_string() -> None:
    assert config_to_toml({}) == ""


def test_escapes_special_characters_in_values() -> None:
    toml = config_to_toml({"redaction": {"digest_key": 'has "quotes" and\nnewlines'}})
    assert '\\"quotes\\"' in toml
    assert "\\n" in toml


# "github-token\n" guards the re.match-vs-fullmatch footgun: `$` matches
# before a trailing newline, so `re.match` would accept it and emit a
# broken `[rules.github-token\n]` header.
@pytest.mark.parametrize(
    "rule_id", ["my.rule", "my]rule", "MyRule", "github-token\n", "github-token\nx"]
)
def test_rejects_invalid_rule_ids(rule_id: str) -> None:
    with pytest.raises(ValueError, match="invalid rule ID"):
        config_to_toml({"rules": {rule_id: {"enabled": False}}})


# ── Integration: round-trip through engine ─────────────────────────


def test_dict_config_accepted_by_engine() -> None:
    engine = create_engine(
        {"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}},
        {"CLOAK_DIGEST_KEY": "test-key"},
    )
    assert engine.redact("hello world").output == b"hello world"
    engine.dispose()


def test_toml_string_config_accepted_by_engine() -> None:
    engine = create_engine(
        '[redaction]\ndigest_key = "env:CLOAK_DIGEST_KEY"\n',
        {"CLOAK_DIGEST_KEY": "test-key"},
    )
    assert engine.redact("hello world").output == b"hello world"
    engine.dispose()


def test_empty_config_accepted_ephemeral_key() -> None:
    engine = create_engine()
    assert engine.redact("hello world").output == b"hello world"
    engine.dispose()


def test_disabled_rule_skips_detection_others_still_work() -> None:
    engine = create_engine(
        {
            "redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"},
            "rules": {"phone-intl": {"enabled": False}},
        },
        {"CLOAK_DIGEST_KEY": "test-key"},
    )
    # phone-intl is disabled; other rules still work.
    output = engine.redact("token=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").output
    assert b"[CLOAK:github-token:" in output
    engine.dispose()
