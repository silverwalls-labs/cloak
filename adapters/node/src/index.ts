/**
 * `cloak-node` — Node.js adapter for cloak secrets redaction.
 *
 * Thin glue over the `cloak-wasm` artifact via built-in
 * `WebAssembly`/`node:wasi`. Zero runtime dependencies.
 *
 * @example
 * ```ts
 * import { createEngine, createCloakTransform } from 'cloak-node';
 *
 * const engine = await createEngine({
 *   redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
 * });
 *
 * // One-shot
 * const redacted = engine.redact('token=ghp_AAAA...AAAA');
 *
 * // Streaming
 * const transform = createCloakTransform(engine);
 * process.stdin.pipe(transform).pipe(process.stdout);
 * ```
 *
 * @packageDocumentation
 */

// Core API
export {
  createEngine,
  CloakError,
  type CloakConfig,
  type CloakEngine,
  type CloakSession,
  type CloakStats,
  type RedactResult,
} from "./engine.ts";

// Config types (re-exported for convenience)
export type { RedactionConfig, RuleConfig } from "./config.ts";

// Node.js Transform stream
export { createCloakTransform } from "./transform.ts";

// Web TransformStream
export { createCloakTransformStream } from "./web-transform.ts";
