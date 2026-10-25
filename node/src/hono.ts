import { createVerifier } from "./core.js";
import { DEFAULT_MAX_BODY_BYTES, PAYLOAD_TOO_LARGE, headersSayBody, readLimited, rejectionBody, type AdapterOptions } from "./reject.js";

// Structural types so hono stays an optional peer dependency.
interface Ctx {
  req: { raw: Request; arrayBuffer(): Promise<ArrayBuffer> };
  body(data: string, status: number, headers: Record<string, string>): unknown;
}
export type AssayHonoMiddleware = (c: Ctx, next: () => Promise<void>) => Promise<unknown>;

/** Hono middleware: `app.use("*", assayVerify())`. Hono caches the body, so handlers can still read it. */
export function assayVerify(options: AdapterOptions): AssayHonoMiddleware {
  const verify = createVerifier(options);
  const max = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  return async (c, next) => {
    const req = c.req.raw;
    // Read a clone with a cap; Hono's own body reading for handlers is untouched.
    const bytes = await readLimited(req.clone(), max);
    if (bytes === null) return c.body(PAYLOAD_TOO_LARGE, 413, { "content-type": "application/json" });
    const result = await verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: bytes.length > 0 || req.body !== null || headersSayBody(req.headers) ? bytes : null,
    });
    if (!result.ok) return c.body(rejectionBody(result.reason), 401, { "content-type": "application/json" });
    await next();
  };
}
