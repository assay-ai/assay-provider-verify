import { createVerifier, type VerifyOptions } from "./core.js";
import { rejectionBody } from "./reject.js";

// Structural types so hono stays an optional peer dependency.
interface Ctx {
  req: { raw: Request; arrayBuffer(): Promise<ArrayBuffer> };
  body(data: string, status: number, headers: Record<string, string>): unknown;
}
export type AssayHonoMiddleware = (c: Ctx, next: () => Promise<void>) => Promise<unknown>;

/** Hono middleware: `app.use("*", assayVerify())`. Hono caches the body, so handlers can still read it. */
export function assayVerify(options: VerifyOptions = {}): AssayHonoMiddleware {
  const verify = createVerifier(options);
  return async (c, next) => {
    const req = c.req.raw;
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    const result = await verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body === null && bytes.length === 0 ? null : bytes,
    });
    if (!result.ok) return c.body(rejectionBody(result.reason), 401, { "content-type": "application/json" });
    await next();
  };
}
