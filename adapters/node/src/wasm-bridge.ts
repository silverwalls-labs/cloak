/**
 * Low-level bridge to the `cloak-wasm` linear-memory ABI.
 *
 * Mirrors the `WasmCloak` helper in `crates/wasm-parity/tests/parity.rs` —
 * same protocol, JS idioms. All pointer/handle juggling is confined here;
 * the rest of the adapter works with `Buffer` values.
 *
 * @internal Not part of the public API — use `createEngine()` instead.
 */

import { WASI } from "node:wasi";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

// ── WASM export types ──────────────────────────────────────────────

/** Typed view of the `cloak-wasm` C-ABI exports. */
interface CloakWasmExports {
  memory: WebAssembly.Memory;
  cloakwasm_alloc(size: number): number;
  cloakwasm_dealloc(ptr: number, size: number): void;
  cloakwasm_engine_new(configPtr: number, configLen: number): number;
  cloakwasm_engine_free(handle: number): number;
  cloakwasm_session_new(engineHandle: number): number;
  cloakwasm_session_free(sessionHandle: number): number;
  cloakwasm_push(
    sessionHandle: number,
    inPtr: number,
    inLen: number,
  ): number;
  cloakwasm_finish(sessionHandle: number): number;
  cloakwasm_finish_stats(): number;
  cloakwasm_redact(
    engineHandle: number,
    inPtr: number,
    inLen: number,
  ): number;
  cloakwasm_buf_free(resultPtr: number): void;
  cloakwasm_last_error(): number;
}

// ── Error type ─────────────────────────────────────────────────────

export class CloakError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CloakError";
  }
}

// ── Bridge ─────────────────────────────────────────────────────────

/**
 * Resolve the `.wasm` artifact path.
 *
 * Priority: `CLOAK_WASM_PATH` env var, then the standard cargo release
 * output relative to this file's location in the repo.
 */
function wasmPath(): string {
  if (process.env["CLOAK_WASM_PATH"]) {
    return process.env["CLOAK_WASM_PATH"];
  }
  // Fallback: standard cargo build output relative to this file.
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(
    thisDir,
    "../../..",
    "target/wasm32-wasip1/release/cloak_wasm.wasm",
  );
}

export class WasmBridge {
  #exports: CloakWasmExports;

  private constructor(exports: CloakWasmExports) {
    this.#exports = exports;
  }

  /**
   * Load the WASM module and initialize the WASI reactor.
   *
   * @param env  Environment variables visible to the WASM module.
   *             Defaults to `process.env` — the digest key is read from
   *             here via `env:CLOAK_DIGEST_KEY` in the config.
   */
  static async create(
    env?: Record<string, string>,
  ): Promise<WasmBridge> {
    const artifactPath = wasmPath();
    const wasmBuffer = await readFile(artifactPath);

    // Filter out undefined values from process.env — WASI expects
    // Record<string, string> and process.env values can be undefined.
    const wasiEnv: Record<string, string> = env ?? Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] => entry[1] !== undefined,
      ),
    );

    const wasi = new WASI({
      version: "preview1",
      env: wasiEnv,
    });

    const module = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(
      module,
      wasi.getImportObject(),
    );
    wasi.initialize(instance);

    return new WasmBridge(
      instance.exports as unknown as CloakWasmExports,
    );
  }

  // ── Linear memory helpers ──────────────────────────────────────

  /** Current view of WASM linear memory (re-read after every call). */
  #mem(): DataView {
    return new DataView(this.#exports.memory.buffer);
  }

  #memU8(): Uint8Array {
    return new Uint8Array(this.#exports.memory.buffer);
  }

  /**
   * Allocate + copy bytes into WASM linear memory.
   * Returns `[ptr, allocSize]` — use `allocSize` for dealloc.
   */
  writeBytes(data: Uint8Array): [ptr: number, allocSize: number] {
    const allocSize = Math.max(data.length, 1);
    const ptr = this.#exports.cloakwasm_alloc(allocSize);
    if (ptr === 0) {
      throw new CloakError(`WASM alloc failed for ${allocSize} bytes`);
    }
    if (data.length > 0) {
      this.#memU8().set(data, ptr);
    }
    return [ptr, allocSize];
  }

  /** Read a `BufResult { ptr: u32, len: u32 }` from linear memory. */
  readBufResult(resultPtr: number): Buffer {
    const view = this.#mem();
    const dataPtr = view.getUint32(resultPtr, true);
    const dataLen = view.getUint32(resultPtr + 4, true);
    if (dataLen === 0) return Buffer.alloc(0);
    // Copy out before any further WASM call can move memory.
    return Buffer.from(
      this.#exports.memory.buffer.slice(dataPtr, dataPtr + dataLen),
    );
  }

  /** Free a `BufResult` and its data buffer. Null-safe. */
  bufFree(resultPtr: number): void {
    if (resultPtr === 0) return;
    this.#exports.cloakwasm_buf_free(resultPtr);
  }

  /** Dealloc a region previously returned by `writeBytes`. */
  dealloc(ptr: number, size: number): void {
    this.#exports.cloakwasm_dealloc(ptr, size);
  }

  // ── Error retrieval ────────────────────────────────────────────

  /** Read and consume the last WASM error message. */
  lastError(): string | null {
    const ptr = this.#exports.cloakwasm_last_error();
    if (ptr === 0) return null;
    const data = this.readBufResult(ptr);
    this.bufFree(ptr);
    return data.toString("utf-8");
  }

  /**
   * Read the last error, throw if one exists.
   * Call after any WASM function that signals failure via a null/zero return.
   */
  throwIfError(context: string): never {
    const err = this.lastError();
    throw new CloakError(
      err ? `${context}: ${err}` : `${context} (no error message)`,
    );
  }

  // ── Engine lifecycle ───────────────────────────────────────────

  engineNew(configToml: string): number {
    const bytes = new TextEncoder().encode(configToml);
    const [ptr, allocSize] = this.writeBytes(bytes);
    const handle = this.#exports.cloakwasm_engine_new(ptr, bytes.length);
    this.dealloc(ptr, allocSize);
    if (handle === 0) this.throwIfError("engine_new");
    return handle;
  }

  engineFree(handle: number): void {
    const rc = this.#exports.cloakwasm_engine_free(handle);
    if (rc === 0) this.throwIfError("engine_free");
  }

  // ── Session lifecycle ──────────────────────────────────────────

  sessionNew(engineHandle: number): number {
    const handle = this.#exports.cloakwasm_session_new(engineHandle);
    if (handle === 0) this.throwIfError("session_new");
    return handle;
  }

  sessionFree(handle: number): void {
    const rc = this.#exports.cloakwasm_session_free(handle);
    if (rc === 0) this.throwIfError("session_free");
  }

  push(sessionHandle: number, input: Uint8Array): Buffer {
    const [ptr, allocSize] = this.writeBytes(input);
    const resultPtr = this.#exports.cloakwasm_push(
      sessionHandle,
      ptr,
      input.length,
    );
    this.dealloc(ptr, allocSize);
    if (resultPtr === 0) this.throwIfError("push");
    const data = this.readBufResult(resultPtr);
    this.bufFree(resultPtr);
    return data;
  }

  finish(sessionHandle: number): Buffer {
    const resultPtr = this.#exports.cloakwasm_finish(sessionHandle);
    if (resultPtr === 0) this.throwIfError("finish");
    const data = this.readBufResult(resultPtr);
    this.bufFree(resultPtr);
    return data;
  }

  finishStats(): Record<string, unknown> | null {
    const ptr = this.#exports.cloakwasm_finish_stats();
    if (ptr === 0) return null;
    const data = this.readBufResult(ptr);
    this.bufFree(ptr);
    return JSON.parse(data.toString("utf-8")) as Record<string, unknown>;
  }

  redact(engineHandle: number, input: Uint8Array): Buffer {
    const [ptr, allocSize] = this.writeBytes(input);
    const resultPtr = this.#exports.cloakwasm_redact(
      engineHandle,
      ptr,
      input.length,
    );
    this.dealloc(ptr, allocSize);
    if (resultPtr === 0) this.throwIfError("redact");
    const data = this.readBufResult(resultPtr);
    this.bufFree(resultPtr);
    return data;
  }
}
