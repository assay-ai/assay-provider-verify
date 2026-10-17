import { createVerifier } from "./core.js";
import { DEFAULT_MAX_BODY_BYTES, PAYLOAD_TOO_LARGE, headersSayBody, readLimited, rejectionBody, type AdapterOptions } from "./reject.js";

/** Next.js route-handler wrapper: `export const POST = withAssayVerify(async (req) => ...)`. */
export function withAssayVerify(
  handler: (req: Request) => Promise<Response>,
  options: AdapterOptions = {},
): (req: Request) => Promise<Response> {
  const verify = createVerifier(options);
  const max = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  return async (req) => {
    const bytes = await readLimited(req.clone(), max);
    if (bytes === null) {
      return new Response(PAYLOAD_TOO_LARGE, { status: 413, headers: { "content-type": "application/json" } });
    }
    const result = await verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: bytes.length > 0 || req.body !== null || headersSayBody(req.headers) ? bytes : null,
    });
    if (!result.ok) {
      return new Response(rejectionBody(result.reason), { status: 401, headers: { "content-type": "application/json" } });
    }
    return handler(req);
  };
}
