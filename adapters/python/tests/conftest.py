"""Shared fixtures for the cloak-python test suite."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import TypedDict

import pytest

from cloak_python import CloakConfig, CloakEngine, create_engine

# Must match KEY_MATERIAL in export-vectors.rs and wasm-parity.
KEY_MATERIAL = "integration-test-key"

CONFIG: CloakConfig = {
    "redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"},
}


class Vector(TypedDict):
    name: str
    input: str  # hex
    expected: str  # hex


def load_vectors() -> list[Vector]:
    raw = (Path(__file__).parent / "fixtures/vectors.json").read_text("utf-8")
    vectors: list[Vector] = json.loads(raw)
    return vectors


VECTORS = load_vectors()


@pytest.fixture(scope="module")
def engine() -> Iterator[CloakEngine]:
    """One engine per test module, configured like the Rust/Node parity suites."""
    engine = create_engine(CONFIG, {"CLOAK_DIGEST_KEY": KEY_MATERIAL})
    yield engine
    engine.dispose()
