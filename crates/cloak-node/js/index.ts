/**
 * `cloak-node-native` — native Node.js binding for cloak secrets redaction.
 *
 * Direct napi-rs binding over `cloak-core` — no WASM runtime, no
 * linear-memory copies. Zero runtime dependencies.
 *
 * @example
 * ```ts
 * import { createEngine, createCloakTransform } from 'cloak-node-native';
 *
 * const engine = createEngine({
 *   redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
 * });
 *
 * // One-shot
 * const { output } = engine.redact('token=ghp_AAAA...AAAA');
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
