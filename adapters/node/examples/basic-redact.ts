/**
 * Basic one-shot redaction — the simplest possible cloak usage.
 *
 * Run:
 *   CLOAK_DIGEST_KEY=my-key node --experimental-strip-types examples/basic-redact.ts
 */

import { createEngine } from "../src/index.ts";

const engine = await createEngine({
  redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
});

// One-shot: string in, { output, stats } out.
const input = "Connecting with token=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 ...";
const { output: redacted, stats: oneStats } = engine.redact(input);
console.log(redacted.toString());
// → Connecting with token=[CLOAK:github-token:xxxx] ...
console.log("One-shot stats:", JSON.stringify(oneStats));

// Streaming: push chunks, finish at the end.
const session = engine.session();
const part1 = session.push("user=alice key=AKIA");
const part2 = session.push("IOSFODNN7EXAMPLE more data\n");
const { output: tail, stats } = session.finish();

const full = Buffer.concat([part1, part2, tail]);
console.log(full.toString());
console.log("Stats:", JSON.stringify(stats));

engine.dispose();
