/**
 * Pino transport (worker thread) — production-grade redaction.
 *
 * Pino transports run in a separate worker thread via `pino.transport()`.
 * This file is the transport entry point: pino spawns it as a worker,
 * pipes serialized log lines into it, and the transport pushes them
 * through cloak before writing to stdout.
 *
 * ## Trade-offs vs. the destination wrapper
 *
 * | | Destination (pino-destination.ts) | Transport (this file) |
 * |---|---|---|
 * | Thread | Main thread | Worker thread |
 * | Latency impact | Blocks the event loop during redaction | None — async I/O in worker |
 * | Setup | Simpler | Requires file-based transport |
 * | Recommended for | Dev, low-throughput | Production, high-throughput |
 *
 * ## Usage
 *
 * ```ts
 * import pino from 'pino';
 *
 * const logger = pino({
 *   transport: {
 *     target: './examples/pino-transport.ts',
 *     options: {
 *       // The transport reads CLOAK_DIGEST_KEY from its own env.
 *     },
 *   },
 * });
 *
 * logger.info({ token: 'ghp_...' }, 'hello');
 * ```
 *
 * Run:
 *   npm install pino  # (devDependency in package.json)
 *   CLOAK_DIGEST_KEY=my-key node --experimental-strip-types examples/pino-transport-demo.ts
 */

import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import { createEngine, createCloakTransform } from "../src/index.ts";

/**
 * Pino transport entry point.
 *
 * Pino calls this function when it spawns the worker. It must return
 * a `Writable` that pino will write serialized log lines into.
 */
export default async function (): Promise<Transform> {
  const engine = await createEngine({
    redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
  });

  const redactor = createCloakTransform(engine);

  // Pipeline: pino → redactor → stdout (in the worker thread).
  // We don't await this — pipeline runs until the source ends.
  pipeline(redactor, process.stdout).catch((err) => {
    // Broken pipe (EPIPE) is expected when the parent exits.
    if ((err as NodeJS.ErrnoException).code !== "EPIPE") {
      console.error("cloak transport pipeline error:", err);
    }
  });

  // Return the writable side — pino writes log lines here.
  return redactor;
}
