"""Off-thread redaction with ``QueueHandler``/``QueueListener``.

The production-grade shape (analog of the Node pino worker transport):
the application thread only enqueues records; a listener thread formats,
redacts, and writes them, keeping WASM calls off the hot path.

Trade-offs vs. the plain handler (``logging_handler.py``):

====================  ==========================  =========================
Aspect                Plain handler               Queue listener (this file)
====================  ==========================  =========================
Thread                Application thread          Listener thread
Latency impact        Blocks caller per record    None — enqueue only
Setup                 Simpler                     Queue + listener lifecycle
Recommended for       Dev, low-throughput         Production, high-throughput
====================  ==========================  =========================

The engine lives entirely on the listener thread — cloak engines are
not thread-safe, and this layout keeps every WASM call on one thread.

Run::

    CLOAK_DIGEST_KEY=my-key uv run python examples/logging_queue.py
"""

import logging
import logging.handlers
import queue

from cloak_python import CloakHandler, create_engine

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

# The CloakHandler runs on the listener thread only.
cloak_handler = CloakHandler(engine)
cloak_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

log_queue: queue.Queue[logging.LogRecord] = queue.Queue()
listener = logging.handlers.QueueListener(log_queue, cloak_handler)
listener.start()

# The application only sees the QueueHandler — enqueue and return.
logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
logger.addHandler(logging.handlers.QueueHandler(log_queue))

# ── Example usage ──────────────────────────────────────────────────

# A fake token — the example exists to show it being redacted on the
# way out (semgrep: python-logger-credential-disclosure).
fake_token = "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"

logger.info("Application starting")
logger.info("User authenticated token=%s", fake_token)  # nosemgrep
logger.warning("External API call failed apiKey=%s", "AKIAIOSFODNN7EXAMPLE")
logger.info("Clean log line — no secrets here")

# Drain the queue, then release everything.
listener.stop()
cloak_handler.close()
engine.dispose()
