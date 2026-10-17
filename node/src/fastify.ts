import { Readable } from "node:stream";
import { createVerifier, type VerifyOptions } from "./core.js";
import { rejectionBody } from "./reject.js";

// Structural types so fastify stays an optional peer dependency.
interface Req { method: string; raw: { url?: string }; headers: Record<string, string | string[] | undefined>; rawBody?: Buffer }
interface Reply { code(n: number): Reply; header(k: string, v: string): Reply; send(b: string): Reply }
interface Instance {
  addHook(name: "preParsing", fn: (req: Req, reply: Reply, payload: AsyncIterable<Buffer | string>) => Promise<unknown>): void;
}

/** Fastify plugin: `app.register(assayVerifyPlugin, options)`. Applies to the whole app (not encapsulated). */
export const assayVerifyPlugin = async (app: Instance, options: VerifyOptions = {}): Promise<void> => {
  const verify = createVerifier(options);
  app.addHook("preParsing", async (req, reply, payload) => {
    const chunks: Buffer[] = [];
    for await (const chunk of payload) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    const raw = Buffer.concat(chunks);
    const hasBody = raw.length > 0 || req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined;
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
