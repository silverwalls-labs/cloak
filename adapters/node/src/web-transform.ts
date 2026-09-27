/**
 * Web Streams API `TransformStream` that redacts secrets on the fly.
 *
 * Same shape as the Node `Transform` stream but using the platform
 * `TransformStream` class (available in Node 18+ globally). Useful for
 * `fetch` response bodies, `ReadableStream.pipeThrough()`, and
 * frameworks that speak Web Streams.
 *
 * @example
 * ```ts
 * import { createEngine, createCloakTransformStream } from 'cloak-node';
 *
 * const engine = await createEngine();
 * const redactor = createCloakTransformStream(engine);
 * const redacted = someReadable.pipeThrough(redactor);
 * ```
 */

import type { CloakEngine, CloakSession } from "./engine.ts";

/**
 * Create a Web `TransformStream` that redacts secrets via cloak.
 *
 * Operates on `Uint8Array` chunks. The engine must outlive the stream.
 */
export function createCloakTransformStream(
  engine: CloakEngine,
): TransformStream<Uint8Array, Uint8Array> {
  let session: CloakSession | null = engine.session();

  // The Transformer type in @types/node omits `cancel` even though the
  // Web Streams spec includes it and Node implements it. We define the
  // object with `cancel` and assert the type so tsc accepts it.
  const transformer: Transformer<Uint8Array, Uint8Array> & {
    cancel?(): void;
  } = {
    transform(
      chunk: Uint8Array,
      controller: TransformStreamDefaultController<Uint8Array>,
    ): void {
      if (!session) {
        controller.error(new Error("cloak transform already finished"));
        return;
      }
      try {
        const out = session.push(Buffer.from(chunk));
        if (out.length > 0) controller.enqueue(new Uint8Array(out));
      } catch (err) {
        // `transformer.cancel()` is NOT invoked when `transform()` throws,
        // so release the session here or it blocks `engine.dispose()`.
        session.abort();
        session = null;
        throw err;
      }
    },

    flush(
      controller: TransformStreamDefaultController<Uint8Array>,
    ): void {
      if (!session) return;
      const { output } = session.finish();
      if (output.length > 0) controller.enqueue(new Uint8Array(output));
      session = null;
    },

    cancel(): void {
      if (session) {
        session.abort();
        session = null;
      }
    },
  };

  return new TransformStream<Uint8Array, Uint8Array>(transformer);
}
