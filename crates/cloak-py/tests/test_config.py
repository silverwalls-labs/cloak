"""Config serialization tests: dict → TOML → engine accepts it.

Mirrors ``adapters/node/test/config.test.ts``.
"""

from __future__ import annotations

import os
from typing import cast

import pytest

from cloak_py import CloakConfig, CloakError, config_to_toml, create_engine

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


def test_escapes_control_characters_in_values() -> None:
    # Raw control chars (other than tab) and DEL are invalid in TOML
    # basic strings. The generated TOML must stay well-formed: without
    # the \uXXXX escapes, the Rust parser fails with a confusing TOML
    # syntax error; with them, core's own config validation answers.
    toml = config_to_toml({"redaction": {"digest_key": "a\x00b\x0bc\x1fd\x7f"}})
    assert '"a\\u0000b\\u000bc\\u001fd\\u007f"' in toml
    with pytest.raises(CloakError, match="invalid digest_key"):
        create_engine(toml)  # parses fine; core rejects the value


@pytest.mark.parametrize("bad", ["yes", 1, None])
def test_rejects_non_bool_enabled(bad: object) -> None:
    # A truthy string like "yes" must not silently serialize as
    # enabled = false (or "True") — reject with a clear TypeError.
    config = cast("CloakConfig", {"rules": {"github-token": {"enabled": bad}}})
    with pytest.raises(TypeError, match="enabled"):
        config_to_toml(config)


@pytest.mark.parametrize("bad", [True, 1, None])
def test_rejects_non_str_digest_key(bad: object) -> None:
    config = cast("CloakConfig", {"redaction": {"digest_key": bad}})
    with pytest.raises(TypeError, match="digest_key"):
        config_to_toml(config)


@pytest.mark.parametrize("bad", [None, "env:X", 1])
def test_rejects_non_mapping_sections(bad: object) -> None:
    config = cast("CloakConfig", {"redaction": bad})
    with pytest.raises(TypeError, match=r"redaction must be a mapping"):
        config_to_toml(config)


def test_rejects_non_mapping_rule_config() -> None:
    config = cast("CloakConfig", {"rules": {"github-token": "nope"}})
    with pytest.raises(TypeError, match=r"rules\.github-token"):
        config_to_toml(config)


def test_rejects_non_str_rule_id() -> None:
    config = cast("CloakConfig", {"rules": {123: {"enabled": True}}})
    with pytest.raises(TypeError, match="rule ID"):
        config_to_toml(config)


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


def test_env_restored_after_failed_engine_build() -> None:
    # The process-wide os.environ swap in create_engine(env=...) must
    # restore the original environment even when the build fails —
    # the finally block must not be skipped.
    before = dict(os.environ)
    with pytest.raises(CloakError, match="invalid config"):
        create_engine(
            '[redaction]\ndigest_key = "not-an-env-reference"\n', {"OTHER": "1"}
        )
    assert dict(os.environ) == before


def test_env_restored_after_successful_build() -> None:
    before = dict(os.environ)
    engine = create_engine(
        {"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}},
        {"CLOAK_DIGEST_KEY": "test-key"},
    )
    assert dict(os.environ) == before
    assert engine.redact(b"clean").output == b"clean"
    engine.dispose()
