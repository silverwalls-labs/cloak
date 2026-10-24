"""Stdlib ``logging`` handler — simple, main-thread redaction.

Every formatted record is redacted before it reaches the stream. Good
for development and simple deployments. For production workloads where
redaction latency must stay off the hot path, see the off-thread
variant in ``logging_queue.py``.

Run::

    CLOAK_DIGEST_KEY=my-key uv run python examples/logging_handler.py
"""

import logging

from cloak_python import CloakHandler, create_engine

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

handler = CloakHandler(engine)  # writes to sys.stdout.buffer
handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# ── Example usage ──────────────────────────────────────────────────

# A fake token — the example exists to show it being redacted on the
# way out (semgrep: python-logger-credential-disclosure).
fake_token = "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"

logger.info("Application starting")
logger.info("User authenticated token=%s", fake_token)  # nosemgrep
logger.warning("External API call failed apiKey=%s", "AKIAIOSFODNN7EXAMPLE")
logger.info("Clean log line — no secrets here")

handler.close()
engine.dispose()
