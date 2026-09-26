/**
 * Node.js `Transform` stream that redacts secrets on the fly.
 *
 * This is the layer-1 stdout/stderr hook shape from the embedding doc:
 * wrap a stream so everything flowing through it is redacted. Hooks are
 * thin sugar — all correctness lives in core.
 *
 * @example
 * ```ts
 * import { createEngine, createCloakTransform } from 'cloak-node';
 *
 * const engine = await createEngine();
 * const redactor = createCloakTransform(engine);
 * process.stdin.pipe(redactor).pipe(process.stdout);
 * ```
 */

import { Transform, type TransformCallback } from "node:stream";

import type { CloakEngine, CloakSession } from "./engine.ts";

/**
 * Create a `Transform` stream that redacts secrets via cloak.
 *
 * Each chunk is pushed through a cloak session; the stream finishes
 * by flushing the session's carry-over. The engine must outlive the
 * stream.
 */
export function createCloakTransform(engine: CloakEngine): Transform {
  let session: CloakSession | null = engine.session();

  return new Transform({
    transform(
      chunk: Buffer,
      _encoding: BufferEncoding,
      callback: TransformCallback,
    ): void {
      if (!session) {
        callback(new Error("cloak transform already finished"));
        return;
      }
      try {
        const out = session.push(chunk);
        if (out.length > 0) this.push(out);
        callback();
      } catch (err) {
        callback(err instanceof Error ? err : new Error(String(err)));
      }
    },

    flush(callback: TransformCallback): void {
      if (!session) {
        callback();
        return;
      }
      try {
        const { output } = session.finish();
        if (output.length > 0) this.push(output);
        session = null;
        callback();
      } catch (err) {
        callback(err instanceof Error ? err : new Error(String(err)));
      }
    },

    destroy(err, callback) {
      // Abort the session on premature destruction (broken pipe, etc.).
      if (session) {
        session.abort();
        session = null;
      }
      callback(err);
    },
  });
}
