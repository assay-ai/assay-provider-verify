import type { IncomingMessage, ServerResponse } from "node:http";
import { createVerifier } from "./core.js";
import { DEFAULT_MAX_BODY_BYTES, PAYLOAD_TOO_LARGE, declaredTooLarge, headersSayBody, rejectionBody, type AdapterOptions } from "./reject.js";

type Req = IncomingMessage & { originalUrl?: string; body?: unknown; rawBody?: Buffer; _body?: boolean };
type Next = (err?: unknown) => void;

function send(res: ServerResponse, status: number, body: string): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(body);
}

async function readBody(req: IncomingMessage, max: number): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const b = typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
    total += b.length;
    if (total > max) return null;
    chunks.push(b);
  }
  return Buffer.concat(chunks);
}

/** Express middleware. Mount BEFORE body parsers: it buffers the raw body, verifies, sets req.rawBody. */
export function assayVerify(options: AdapterOptions): (req: Req, res: ServerResponse, next: Next) => void {
  const verify = createVerifier(options);
  const max = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const run = async (req: Req, res: ServerResponse, next: Next): Promise<void> => {
    if (req._body || req.readableEnded || req.destroyed) {
      send(res, 500, JSON.stringify({ error: "assay_verify_misconfigured", message: "mount assayVerify() before body parsers" }));
      return;
    }
    const tooLarge = (): void => {
      res.setHeader("connection", "close");
      send(res, 413, PAYLOAD_TOO_LARGE);
    };
    if (declaredTooLarge(req.headers, max)) return tooLarge();
    const raw = await readBody(req, max);
    if (raw === null) return tooLarge();
    const hasBody = raw.length > 0 || headersSayBody(req.headers);
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
    req._body = true; // body-parser's "already parsed" flag: later parsers become no-ops
    if (req.body === undefined) {
      const ct = String(req.headers["content-type"] ?? "");
      if (/^application\/(?:[\w.+-]+\+)?json\b/i.test(ct)) {
        try {
          req.body = raw.length > 0 ? JSON.parse(raw.toString("utf8")) : {};
        } catch {
          send(res, 400, JSON.stringify({ error: "invalid_json" }));
          return;
        }
      } else {
        req.body = raw;
      }
    }
    next();
  };
  return (req, res, next) => {
    run(req, res, next).catch(next);
  };
}
