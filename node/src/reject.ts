import type { RejectReason, VerifyOptions } from "./core.js";

/** JSON body for a 401 rejection; identical across adapters and languages. */
export function rejectionBody(reason: RejectReason): string {
  return `{"error":"invalid_assay_signature","reason":"${reason}"}`;
}


/** Default cap for bodies buffered before authentication (5 MiB). */
export const DEFAULT_MAX_BODY_BYTES = 5_242_880;

export interface AdapterOptions extends VerifyOptions {
  /** Maximum request body buffered before verification; larger bodies get 413. Default 5 MiB. */
  maxBodyBytes?: number;
}

export const PAYLOAD_TOO_LARGE = '{"error":"payload_too_large"}';

type HeaderBag = Headers | Record<string, string | string[] | undefined>;

function header(h: HeaderBag, name: string): string | undefined {
  if (typeof (h as Headers).get === "function") return (h as Headers).get(name) ?? undefined;
  const v = (h as Record<string, string | string[] | undefined>)[name];
  return Array.isArray(v) ? v[0] : v;
}

/** True when the declared Content-Length already exceeds the cap. */
export function declaredTooLarge(h: HeaderBag, max: number): boolean {
  const n = Number(header(h, "content-length"));
  return Number.isFinite(n) && n > max;
}

/** A body exists when content-length (even "0") or transfer-encoding is set. */
export function headersSayBody(h: HeaderBag): boolean {
  return header(h, "content-length") !== undefined || header(h, "transfer-encoding") !== undefined;
}

/** Reads a Request body up to max bytes; null when over the cap. */
export async function readLimited(req: Request, max: number): Promise<Uint8Array | null> {
  if (declaredTooLarge(req.headers, max)) return null;
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const ch of chunks) { out.set(ch, o); o += ch.length; }
  return out;
}
