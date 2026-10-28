"""Threading contract tests — native-only surface.

The native binding releases the GIL during scans (the point of E5):
one engine shared across threads must produce byte-identical results,
a session may move across threads (core ``Session`` is ``Send`` since
the E5 core change), and concurrent calls into the *same* session must
fail cleanly (pyo3's runtime borrow check) rather than corrupt state.

No timing-based GIL assertions here — they flake; the receipts bench
is the performance evidence (docs/benchmarks/).
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from cloak_py import CloakEngine, CloakError, create_engine

from .conftest import CONFIG, KEY_MATERIAL

DIRTY = (
    b"INFO user=alice@example.com did a thing\n"
    b"DEBUG token=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 granted\n"
    b"WARN key=AKIAIOSFODNN7EXAMPLE exposed\n"
) * 50


def test_shared_engine_concurrent_redact_is_byte_identical(
    engine: CloakEngine,
) -> None:
    baseline = engine.redact(DIRTY).output

    def worker() -> list[bytes]:
        return [engine.redact(DIRTY).output for _ in range(50)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [f.result() for f in [pool.submit(worker) for _ in range(4)]]

    for outputs in results:
        for out in outputs:
            assert out == baseline, "concurrent redact diverged from baseline"


def test_session_moves_across_threads(engine: CloakEngine) -> None:
    baseline = engine.redact(DIRTY).output
    session = engine.session()  # created on the main thread

    chunks: list[bytes] = []

    def worker() -> None:  # pushed and finished on a worker thread
        chunks.append(session.push(DIRTY))
        chunks.append(session.finish().output)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert b"".join(chunks) == baseline


def test_concurrent_push_on_one_session_fails_cleanly(
    engine: CloakEngine,
) -> None:
    # Large enough that the GIL-released scan runs for a good while, so
    # the second push below lands mid-scan.
    big = b"clean log line with no secrets at all\n" * (48 * 1024 * 1024 // 38)
    session = engine.session()
    started = threading.Event()
    errors: list[BaseException] = []

    def long_push() -> None:
        started.set()
        try:
            session.push(big)
        except BaseException as exc:  # recorded and asserted below
            errors.append(exc)

    thread = threading.Thread(target=long_push)
    thread.start()
    started.wait()
    time.sleep(0.01)
    overlapped = True
    try:
        session.push(b"x")
    except RuntimeError as exc:
        # pyo3's runtime borrow check: the worker thread holds the
        # session's &mut for the duration of its detached scan.
        assert "borrow" in str(exc).lower()
    else:
        overlapped = False
    thread.join()
    session.abort()

    if errors:
        # Freak scheduling: the worker lost the race instead — the same
        # clean borrow error must surface on its side.
        assert all(
            isinstance(e, RuntimeError) and "borrow" in str(e).lower() for e in errors
        ), f"background push must fail cleanly if at all: {errors!r}"
    elif not overlapped:
        pytest.skip("pushes did not overlap on this run; borrow path not exercised")


def test_dispose_during_inflight_scan_is_a_coherent_cloak_error() -> None:
    # A dispose landing mid-scan must raise CloakError ("while in use"),
    # never pyo3's borrow-check RuntimeError("Already borrowed") — that
    # is why dispose is `&self` with an internal lock, not `&mut self`.
    # The session created up front pins the engine Arc, so the refusal
    # is deterministic whether or not the scan is still running when
    # dispose lands.
    engine = create_engine(CONFIG, {"CLOAK_DIGEST_KEY": KEY_MATERIAL})
    session = engine.session()
    big = b"clean log line with no secrets at all\n" * (16 * 1024 * 1024 // 38)

    def scanner() -> None:
        engine.redact(big)

    thread = threading.Thread(target=scanner)
    thread.start()
    time.sleep(0.05)  # dispose lands mid-scan (~16 MB, far from done)
    with pytest.raises(CloakError, match="in use"):
        engine.dispose()
    thread.join()

    # A refused dispose leaves the engine usable; it succeeds once the
    # session is released and the scan has completed.
    assert engine.redact(b"clean").output == b"clean"
    session.abort()
    engine.dispose()
    with pytest.raises(CloakError, match="engine disposed"):
        engine.redact(b"x")
