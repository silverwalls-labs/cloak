"""Pipe stdin through cloak to stdout — the layer-1 hook shape.

This is the Python equivalent of ``app | cloak`` but in-process:
wrap your stdout stream so secrets are redacted before they leave.

Run::

    echo "token=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" | \\
      CLOAK_DIGEST_KEY=my-key uv run python examples/stdout_pipe.py
"""

import sys

from cloak_python import CloakWriter, create_engine

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

# Pipe: stdin → cloak → stdout
with CloakWriter(engine, sys.stdout.buffer) as redactor:
    while chunk := sys.stdin.buffer.read(64 * 1024):
        redactor.write(chunk)

engine.dispose()
