import type { IncomingMessage, ServerResponse } from "node:http";
import { createVerifier, type VerifyOptions } from "./core.js";
import { rejectionBody } from "./reject.js";

type Req = IncomingMessage & { originalUrl?: string; body?: unknown; rawBody?: Buffer; _body?: boolean };
type Next = (err?: unknown) => void;

function send(res: ServerResponse, status: number, body: string): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(body);
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  return Buffer.concat(chunks);
}

/** Express middleware. Mount BEFORE body parsers: it buffers the raw body, verifies, sets req.rawBody. */
export function assayVerify(options: VerifyOptions = {}): (req: Req, res: ServerResponse, next: Next) => void {
  const verify = createVerifier(options);
  const run = async (req: Req, res: ServerResponse, next: Next): Promise<void> => {
    if (req._body || req.readableEnded || req.destroyed) {
      send(res, 500, JSON.stringify({ error: "assay_verify_misconfigured", message: "mount assayVerify() before body parsers" }));
      return;
    }
    const raw = await readBody(req);
    const hasBody = raw.length > 0 || req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined;
    const result = await verify({
      method: req.method ?? "GET",
      url: req.originalUrl ?? req.url ?? "/",
      headers: req.headers,
      body: hasBody ? new Uint8Array(raw.buffer, raw.byteOffset, raw.length) : null,
    });
    if (!result.ok) {
      send(res, 401, rejectionBody(result.reason));
      return;
    }
    req.rawBody = raw;
    const ct = String(req.headers["content-type"] ?? "");
    if (req.body === undefined && raw.length > 0 && /^application\/(?:[\w.+-]+\+)?json\b/i.test(ct)) {
      try {
        req.body = JSON.parse(raw.toString("utf8"));
      } catch {
        send(res, 400, JSON.stringify({ error: "invalid_json" }));
        return;
      }
    }
    next();
  };
  return (req, res, next) => {
    run(req, res, next).catch(next);
  };
}
