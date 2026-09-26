/**
 * Pipe stdin through cloak to stdout — the layer-1 hook shape.
 *
 * This is the Node.js equivalent of `app | cloak` but in-process:
 * wrap your stdout stream so secrets are redacted before they leave.
 *
 * Run:
 *   echo "token=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" | \
 *     CLOAK_DIGEST_KEY=my-key node --experimental-strip-types examples/transform-pipe.ts
 */

import { createEngine, createCloakTransform } from "../src/index.ts";

const engine = await createEngine({
  redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
});

const redactor = createCloakTransform(engine);

// Pipe: stdin → cloak → stdout
process.stdin.pipe(redactor).pipe(process.stdout);

// Clean up when done.
redactor.on("end", () => engine.dispose());
