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

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(
      chunk: Uint8Array,
      controller: TransformStreamDefaultController<Uint8Array>,
    ): void {
      if (!session) {
        controller.error(new Error("cloak transform already finished"));
        return;
      }
      const out = session.push(Buffer.from(chunk));
      if (out.length > 0) controller.enqueue(new Uint8Array(out));
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
  });
}
