"""Basic one-shot redaction — the simplest possible cloak usage.

Run::

    CLOAK_DIGEST_KEY=my-key uv run python examples/basic_redact.py
"""

import json

from cloak_python import create_engine

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

# One-shot: string in, (output, stats) out.
text = "Connecting with token=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 ..."
redacted, one_stats = engine.redact(text)
print(redacted.decode())
# → Connecting with token=[CLOAK:github-token:xxxx] ...
print("One-shot stats:", json.dumps(one_stats))

# Streaming: push chunks, finish at the end.
session = engine.session()
part1 = session.push("user=alice key=AKIA")
part2 = session.push("IOSFODNN7EXAMPLE more data\n")
tail, stats = session.finish()

print((part1 + part2 + tail).decode(), end="")
print("Stats:", json.dumps(stats))

engine.dispose()
