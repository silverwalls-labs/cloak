/**
 * High-level cloak engine and session API.
 *
 * Wraps the WASM bridge in a Node-idiomatic interface: `Buffer` in/out,
 * `string` convenience, proper error throwing.
 */

import { WasmBridge, CloakError } from "./wasm-bridge.ts";
import { type CloakConfig, configToToml } from "./config.ts";

export { CloakError };
export type { CloakConfig };

// ── Types ──────────────────────────────────────────────────────────

/** Per-stream statistics returned by `session.finish()`. */
export interface CloakStats {
  /** Total bytes pushed through the session. */
  bytes_processed: number;
  /** Per-rule match counts (rule-id → count). */
  matches: Record<string, number>;
}

/** A scanning session — per-stream state, cheap to create. */
export interface CloakSession {
  /**
   * Push a chunk through the scanner.
   *
   * Returns redacted bytes flushed by this push (may be empty when all
   * bytes are held in the carry-over window). String inputs are encoded
   * as UTF-8.
   */
  push(input: string | Buffer | Uint8Array): Buffer;

  /**
   * Finish the session: flush carry-over and return redacted output + stats.
   *
   * The session handle is consumed — do not reuse after this call.
   */
  finish(): { output: Buffer; stats: CloakStats };

  /**
   * Abort the session without flushing.
   *
   * Drops carry-over and releases the session handle. Use when a stream
   * is abandoned mid-way.
   */
  abort(): void;
}

/** Result of a one-shot `redact()` call. */
export interface RedactResult {
  /** The redacted output bytes. */
  output: Buffer;
  /** Per-stream statistics (same shape as `session.finish()`). */
  stats: CloakStats;
}

/** A compiled cloak engine — create sessions from it. */
export interface CloakEngine {
  /**
   * One-shot convenience: redact a complete buffer in one call.
   *
   * Equivalent to `session() → push(all) → finish()` but without the
   * session lifecycle. String inputs are encoded as UTF-8. Returns both
   * the redacted output and per-stream stats.
   */
  redact(input: string | Buffer | Uint8Array): RedactResult;

  /**
   * Create a new scanning session for streaming redaction.
   *
   * Sessions are cheap — one per stream/request. The engine must
   * outlive all its sessions.
   */
  session(): CloakSession;

  /**
   * Release the engine and its WASM resources.
   *
   * Fails if any sessions created from this engine are still live —
   * finish or abort them first.
   */
  dispose(): void;
}

// ── Helpers ────────────────────────────────────────────────────────

/** Coerce `string | Buffer | Uint8Array` to `Uint8Array`. */
function toBytes(input: string | Buffer | Uint8Array): Uint8Array {
  if (typeof input === "string") return Buffer.from(input, "utf-8");
  return input;
}

// ── Factory ────────────────────────────────────────────────────────

/**
 * Create a new cloak engine.
 *
 * Loads the WASM module (async), compiles the config, and returns a
 * ready-to-use engine. Call with no arguments for the default config
 * (ephemeral digest key, all rules enabled).
 *
 * @param config  Engine configuration (JS object, serialized to TOML).
 * @param env     Environment variables visible to the WASM module.
 *                Defaults to `process.env`.
 *
 * @example
 * ```ts
 * const engine = await createEngine({
 *   redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
 * });
 * const redacted = engine.redact('token=ghp_AAAA...AAAA');
 * engine.dispose();
 * ```
 */
export async function createEngine(
  config?: CloakConfig | string,
  env?: Record<string, string>,
): Promise<CloakEngine> {
  const bridge = await WasmBridge.create(env);

  let toml: string;
  if (config === undefined) {
    toml = "";
  } else if (typeof config === "string") {
    toml = config;
  } else {
    toml = configToToml(config);
  }

  const engineHandle = bridge.engineNew(toml);

  const engine: CloakEngine = {
    redact(input: string | Buffer | Uint8Array): RedactResult {
      const output = bridge.redact(engineHandle, toBytes(input));
      const rawStats = bridge.finishStats();
      const stats: CloakStats = rawStats
        ? (rawStats as unknown as CloakStats)
        : { bytes_processed: 0, matches: {} };
      return { output, stats };
    },

    session(): CloakSession {
      const sessionHandle = bridge.sessionNew(engineHandle);
      let consumed = false;

      return {
        push(input: string | Buffer | Uint8Array): Buffer {
          if (consumed) {
            throw new CloakError(
              "session already consumed (finished or aborted)",
            );
          }
          return bridge.push(sessionHandle, toBytes(input));
        },

        finish(): { output: Buffer; stats: CloakStats } {
          if (consumed) {
            throw new CloakError(
              "session already consumed (finished or aborted)",
            );
          }
          consumed = true;
          const output = bridge.finish(sessionHandle);
          const rawStats = bridge.finishStats();
          const stats: CloakStats = rawStats
            ? (rawStats as unknown as CloakStats)
            : { bytes_processed: 0, matches: {} };
          return { output, stats };
        },

        abort(): void {
          if (consumed) return; // idempotent
          consumed = true;
          bridge.sessionFree(sessionHandle);
        },
      };
    },

    dispose(): void {
      bridge.engineFree(engineHandle);
    },
  };

  return engine;
}
