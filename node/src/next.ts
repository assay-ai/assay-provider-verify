import { createVerifier, type VerifyOptions } from "./core.js";
import { rejectionBody } from "./reject.js";

/** Next.js route-handler wrapper: `export const POST = withAssayVerify(async (req) => ...)`. */
export function withAssayVerify(
  handler: (req: Request) => Promise<Response>,
  options: VerifyOptions = {},
): (req: Request) => Promise<Response> {
  const verify = createVerifier(options);
  return async (req) => {
    const bytes = new Uint8Array(await req.clone().arrayBuffer());
    const result = await verify({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body === null && bytes.length === 0 ? null : bytes,
    });
    if (!result.ok) {
      return new Response(rejectionBody(result.reason), { status: 401, headers: { "content-type": "application/json" } });
    }
    return handler(req);
  };
}
