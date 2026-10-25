import { Readable } from "node:stream";
import { createVerifier } from "./core.js";
import { DEFAULT_MAX_BODY_BYTES, PAYLOAD_TOO_LARGE, declaredTooLarge, headersSayBody, rejectionBody, type AdapterOptions } from "./reject.js";

// Structural types so fastify stays an optional peer dependency.
interface Req { method: string; raw: { url?: string }; headers: Record<string, string | string[] | undefined>; rawBody?: Buffer }
interface Reply { code(n: number): Reply; header(k: string, v: string): Reply; send(b: string): Reply }
interface Instance {
  addHook(name: "preParsing", fn: (req: Req, reply: Reply, payload: AsyncIterable<Buffer | string>) => Promise<unknown>): void;
}

/** Fastify plugin: `app.register(assayVerifyPlugin, options)`. Applies to the whole app (not encapsulated). */
export const assayVerifyPlugin = async (app: Instance, options: AdapterOptions): Promise<void> => {
  const verify = createVerifier(options);
  const max = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  app.addHook("preParsing", async (req, reply, payload) => {
    const tooLarge = () => {
      reply.code(413).header("content-type", "application/json").send(PAYLOAD_TOO_LARGE);
      return reply;
    };
    if (declaredTooLarge(req.headers, max)) return tooLarge();
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of payload) {
      const b = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      total += b.length;
      if (total > max) return tooLarge();
      chunks.push(b);
    }
    const raw = Buffer.concat(chunks);
    const hasBody = raw.length > 0 || headersSayBody(req.headers);
    const result = await verify({
      method: req.method,
      url: req.raw.url ?? "/",
      headers: req.headers,
      body: hasBody ? new Uint8Array(raw.buffer, raw.byteOffset, raw.length) : null,
    });
    if (!result.ok) {
      reply.code(401).header("content-type", "application/json").send(rejectionBody(result.reason));
      return reply;
    }
    req.rawBody = raw;
    return Readable.from([raw]);
  });
};
// Equivalent of fastify-plugin: do not encapsulate, so the hook covers all routes.
(assayVerifyPlugin as unknown as Record<symbol, unknown>)[Symbol.for("skip-override")] = true;
(assayVerifyPlugin as unknown as Record<symbol, unknown>)[Symbol.for("fastify.display-name")] = "assay-verify";
