import { MemoryReplayStore, createVerifier } from "@assay-ai/provider-verify";
import type { ReplayStore, VerifyOptions } from "@assay-ai/provider-verify";

export interface Env {
  ORIGIN_URL: string;
  JWKS_URL?: string;
  /** Optional shared secret sent to the origin as `x-assay-origin-secret`. */
  ORIGIN_SECRET?: string;
  NONCE_STORE?: DurableObjectNamespace;
  /** Optional Durable Object location hint, for example "enam" or "weur". */
  NONCE_LOCATION_HINT?: string;
}

const MAX_BODY_BYTES = 5_242_880;
const STRIP = ["signature", "signature-input", "content-digest", "host"];
const JSON_HEADERS = { "content-type": "application/json" };

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: JSON_HEADERS });
}

/** Reads the body up to the cap; null when it is larger. */
async function readLimited(req: Request, max: number): Promise<Uint8Array | null> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) return null;
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
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/** Cross-instance replay store backed by the NonceStore Durable Object. */
export function durableReplayStore(ns: DurableObjectNamespace, locationHint?: string): ReplayStore {
  return {
    async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
      const id = ns.idFromName("nonces");
      const stub = locationHint ? ns.get(id, { locationHint: locationHint as DurableObjectLocationHint }) : ns.get(id);
      const res = await stub.fetch("https://nonce-store/check", {
        method: "POST",
        body: JSON.stringify({ nonce, ttlSeconds }),
      });
      const { seen } = (await res.json()) as { seen: boolean };
      return !seen; // true = first time seen, as the ReplayStore contract requires
    },
  };
}

// Per-isolate state. Memory is NOT shared between Worker instances.
const memoryStore = new MemoryReplayStore();
type Verify = ReturnType<typeof createVerifier>;
const verifiers = new Map<string, Verify>();

function verifierFor(env: Env, extra: VerifyOptions): Verify {
  const useDo = Boolean(env.NONCE_STORE);
  const key = `${env.JWKS_URL ?? ""}|${useDo ? "do:" + (env.NONCE_LOCATION_HINT ?? "") : "mem"}`;
  const cached = extra.replayStore || extra.jwks ? undefined : verifiers.get(key);
  if (cached) return cached;
  const v = createVerifier({
    replayStore: env.NONCE_STORE ? durableReplayStore(env.NONCE_STORE, env.NONCE_LOCATION_HINT) : memoryStore,
    ...(env.JWKS_URL ? { jwksUrl: env.JWKS_URL } : {}),
    ...extra,
  });
  if (!extra.replayStore && !extra.jwks) verifiers.set(key, v);
  return v;
}

/** Builds the Worker. `extra` lets tests inject keys, a clock or a replay store. */
export function createWorker(extra: VerifyOptions = {}) {
  return {
    async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
      const url = new URL(request.url);
      const bytes = await readLimited(request.clone(), MAX_BODY_BYTES);
      if (bytes === null) return json(413, '{"error":"payload_too_large"}');
      const hasBody =
        bytes.length > 0 ||
        request.body !== null ||
        request.headers.get("content-length") !== null ||
        request.headers.get("transfer-encoding") !== null;

      // Authority is the incoming request's own host.
      const authorityHeaders = new Headers(request.headers);
      authorityHeaders.set("host", url.host);
      const result = await verifierFor(env, extra)({
        method: request.method,
        url: request.url,
        headers: authorityHeaders,
        body: hasBody ? bytes : null,
      });
      if (!result.ok) {
        return json(401, `{"error":"invalid_assay_signature","reason":"${result.reason}"}`);
      }

      const base = new URL(env.ORIGIN_URL);
      const target = new URL(base.origin);
      target.pathname = base.pathname.replace(/\/$/, "") + url.pathname;
      target.search = url.search;

      const headers = new Headers(request.headers);
      for (const h of STRIP) headers.delete(h);
      if (env.ORIGIN_SECRET) headers.set("x-assay-origin-secret", env.ORIGIN_SECRET);

      return fetch(target.toString(), {
        method: request.method,
        headers,
        body: hasBody && bytes.length > 0 ? bytes : undefined,
        redirect: "manual",
      });
    },
  };
}

export default createWorker();

/**
 * Optional Durable Object remembering nonces so replays are caught across all
 * Worker instances. Entries expire through an alarm.
 */
export class NonceStore implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const { nonce, ttlSeconds } = (await request.json()) as { nonce: string; ttlSeconds: number };
    const storage = this.state.storage;
    const now = Date.now();
    const existing = await storage.get<number>(nonce);
    if (existing !== undefined && existing > now) return Response.json({ seen: true });
    const expiresAt = now + ttlSeconds * 1000;
    await storage.put(nonce, expiresAt);
    const alarm = await storage.getAlarm();
    if (alarm === null || alarm > expiresAt) await storage.setAlarm(expiresAt);
    return Response.json({ seen: false });
  }

  async alarm(): Promise<void> {
    const storage = this.state.storage;
    const now = Date.now();
    const all = await storage.list<number>();
    let next: number | null = null;
    const expired: string[] = [];
    for (const [k, exp] of all) {
      if (exp <= now) expired.push(k);
      else if (next === null || exp < next) next = exp;
    }
    if (expired.length) await storage.delete(expired);
    if (next !== null) await storage.setAlarm(next);
  }
}
