/**
 * Pino destination wrapper — simple, main-thread redaction.
 *
 * Wraps a destination `Writable` so every log line is redacted before
 * writing. Good for development and simple deployments. For production
 * workloads with high throughput, consider the worker-thread transport
 * in `pino-transport.ts`.
 *
 * Run:
 *   npm install pino  # (devDependency in package.json)
 *   CLOAK_DIGEST_KEY=my-key node --experimental-strip-types examples/pino-destination.ts
 */

import { Writable } from "node:stream";
import pino from "pino";
import { createEngine, createCloakTransform } from "../src/index.ts";

// Create the cloak engine and a Transform stream.
const engine = await createEngine({
  redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
});

const redactor = createCloakTransform(engine);

// Pipe the redactor into stdout — pino writes to the redactor's
// input side, cloak redacts, stdout gets the cleaned output.
redactor.pipe(process.stdout);

// Create a pino logger that writes to the redactor stream.
const logger = pino(
  { level: "info" },
  // pino.destination wraps a fd/stream; here we write directly to
  // the Transform so every log line flows through cloak.
  redactor as unknown as Writable,
);

// ── Example usage ──────────────────────────────────────────────────

logger.info("Application starting");
logger.info(
  { token: "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" },
  "User authenticated",
);
logger.warn(
  { apiKey: "AKIAIOSFODNN7EXAMPLE" },
  "External API call failed",
);
logger.info("Clean log line — no secrets here");

// Let the stream finish before exiting.
redactor.end(() => {
  engine.dispose();
});
