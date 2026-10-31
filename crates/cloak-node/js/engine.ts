/**
 * High-level cloak engine and session API (native binding).
 *
 * Wraps the napi-rs native module in a Node-idiomatic interface:
 * `Buffer` in/out, `string` convenience, proper error throwing.
 * Unlike the WASM adapter, `createEngine` is **synchronous** — no
 * WASM compilation step.
 */

import { NapiEngine, type NapiSession } from "../index.js";
import { type CloakConfig, configToToml } from "./config.ts";

// ── Error ─────────────────────────────────────────────────────────

/** Error raised for cloak engine/session failures. */
export class CloakError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CloakError";
  }
}

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
   * Release the engine and its native resources.
   *
   * Fails if any sessions created from this engine are still live —
   * finish or abort them first.
   */
  dispose(): void;
}

export type { CloakConfig };

// ── Helpers ────────────────────────────────────────────────────────

/** Coerce `string | Buffer | Uint8Array` to `Buffer`. */
function toBytes(input: string | Buffer | Uint8Array): Buffer {
  if (typeof input === "string") return Buffer.from(input, "utf-8");
  if (Buffer.isBuffer(input)) return input;
  return Buffer.from(input);
}

// ── Factory ────────────────────────────────────────────────────────

/**
 * Create a new cloak engine (synchronous).
 *
 * Compiles the config and returns a ready-to-use engine. Call with no
 * arguments for the default config (ephemeral digest key, all rules
 * enabled).
 *
 * When `env` is provided, `process.env` is temporarily swapped to
 * `env` during construction (the native engine reads env vars exactly
 * once, in its constructor). The swap is safe on the main thread (no
 * concurrent JS can observe the intermediate state within a single
 * tick), but `process.env` is backed by the OS environment, which
 * `worker_threads` share — if a worker calls `createEngine` with
 * `env` while another thread reads `process.env`, the other thread
 * may see the swapped values. Create engines with custom `env` on
 * only one thread, or pass the digest key inline instead of via
 * `env:` indirection.
 *
 * @param config  Engine configuration (JS object serialized to TOML,
 *                or a raw TOML string).
 * @param env     Environment variables visible during engine construction.
 *                Defaults to the current `process.env`.
 *
 * @example
 * ```ts
 * const engine = createEngine({
 *   redaction: { digestKey: 'env:CLOAK_DIGEST_KEY' },
 * });
 * const { output } = engine.redact('token=ghp_AAAA...AAAA');
 * engine.dispose();
 * ```
 */
export function createEngine(
  config?: CloakConfig | string,
  env?: Record<string, string>,
): CloakEngine {
  let toml: string;
  try {
    if (config === undefined) {
      toml = "";
    } else if (typeof config === "string") {
      toml = config;
    } else {
      toml = configToToml(config);
    }
  } catch (err) {
    throw new CloakError(
      err instanceof Error ? err.message : String(err),
    );
  }

  let native: NapiEngine;

  try {
    if (env !== undefined) {
      // Swap process.env for the duration of engine construction, same
      // pattern as cloak-py's create_engine(env=...).
      const orig = { ...process.env };
      try {
        // Clear and repopulate — process.env is a special object, we
        // can't reassign it, only mutate its properties.
        for (const key of Object.keys(process.env)) {
          delete process.env[key];
        }
        Object.assign(process.env, env);
        native = new NapiEngine(toml);
      } finally {
        for (const key of Object.keys(process.env)) {
          delete process.env[key];
        }
        Object.assign(process.env, orig);
      }
    } else {
      native = new NapiEngine(toml);
    }
  } catch (err) {
    throw new CloakError(
      err instanceof Error ? err.message : String(err),
    );
  }

  const engine: CloakEngine = {
    redact(input: string | Buffer | Uint8Array): RedactResult {
      try {
        const result = native.redact(toBytes(input));
        // napi-rs already returns a proper Node.js Buffer — no copy needed.
        return {
          output: result.output as Buffer,
          stats: result.stats as CloakStats,
        };
      } catch (err) {
        throw new CloakError(
          err instanceof Error ? err.message : String(err),
        );
      }
    },

    session(): CloakSession {
      let nativeSession: NapiSession;
      try {
        nativeSession = native.session();
      } catch (err) {
        throw new CloakError(
          err instanceof Error ? err.message : String(err),
        );
      }
      let consumed = false;

      return {
        push(input: string | Buffer | Uint8Array): Buffer {
          if (consumed) {
            throw new CloakError(
              "session already consumed (finished or aborted)",
            );
          }
          try {
            return nativeSession.push(toBytes(input)) as Buffer;
          } catch (err) {
            throw new CloakError(
              err instanceof Error ? err.message : String(err),
            );
          }
        },

        finish(): { output: Buffer; stats: CloakStats } {
          if (consumed) {
            throw new CloakError(
              "session already consumed (finished or aborted)",
            );
          }
          consumed = true;
          try {
            const result = nativeSession.finish();
            return {
              output: result.output as Buffer,
              stats: result.stats as CloakStats,
            };
          } catch (err) {
            throw new CloakError(
              err instanceof Error ? err.message : String(err),
            );
          }
        },

        abort(): void {
          if (consumed) return; // idempotent
          consumed = true;
          nativeSession.abort();
        },
      };
    },

    dispose(): void {
      try {
        native.dispose();
      } catch (err) {
        throw new CloakError(
          err instanceof Error ? err.message : String(err),
        );
      }
    },
  };

  return engine;
}
