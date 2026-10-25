import { MemoryReplayStore, createVerifier } from "@goassay-ai/provider-verify";
import type { ReplayStore, VerifyOptions } from "@goassay-ai/provider-verify";

export interface Env {
  ORIGIN_URL: string;
  /**
   * Required. Your Assay provider id (shown in the portal); several ids may be
   * given comma-separated. Requests signed for any other provider are refused.
   * Without it the Worker answers 500 and never calls the origin.
   */
  ASSAY_PROVIDER_ID?: string;
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

function misconfigured(message: string): Response {
  return json(500, JSON.stringify({ error: "assay_verify_misconfigured", message }));
}

/** Provider ids from ASSAY_PROVIDER_ID (comma-separated); empty when unset. */
export function providerIds(env: Env): string[] {
  return (env.ASSAY_PROVIDER_ID ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0);
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

/** Thrown when the NonceStore Durable Object cannot answer; the Worker fails closed with 503. */
export class ReplayStoreUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReplayStoreUnavailableError";
  }
}

/** Cross-instance replay store backed by the NonceStore Durable Object. */
export function durableReplayStore(ns: DurableObjectNamespace, locationHint?: string): ReplayStore {
  return {
    async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
      let seen: unknown;
      try {
        const id = ns.idFromName("nonces");
        const stub = locationHint ? ns.get(id, { locationHint: locationHint as DurableObjectLocationHint }) : ns.get(id);
        const res = await stub.fetch("https://nonce-store/check", {
          method: "POST",
          body: JSON.stringify({ nonce, ttlSeconds }),
        });
        if (!res.ok) throw new Error(`NonceStore answered ${res.status}`);
        seen = ((await res.json()) as { seen?: unknown }).seen;
      } catch (e) {
        throw new ReplayStoreUnavailableError(e instanceof Error ? e.message : String(e));
      }
      if (typeof seen !== "boolean") throw new ReplayStoreUnavailableError("NonceStore answered without a seen flag");
      return !seen; // true = first time seen, as the ReplayStore contract requires
    },
  };
}

// Per-isolate state. Memory is NOT shared between Worker instances.
const memoryStore = new MemoryReplayStore();
type Verify = ReturnType<typeof createVerifier>;
const verifiers = new Map<string, Verify>();

/** Options the Worker takes from its environment rather than from code. */
export type WorkerOptions = Omit<VerifyOptions, "provider">;

function verifierFor(env: Env, providers: string[], extra: WorkerOptions): Verify {
  const useDo = Boolean(env.NONCE_STORE);
  const key = `${providers.join(",")}|${env.JWKS_URL ?? ""}|${useDo ? "do:" + (env.NONCE_LOCATION_HINT ?? "") : "mem"}`;
  const cached = extra.replayStore || extra.jwks ? undefined : verifiers.get(key);
  if (cached) return cached;
  const v = createVerifier({
    replayStore: env.NONCE_STORE ? durableReplayStore(env.NONCE_STORE, env.NONCE_LOCATION_HINT) : memoryStore,
    ...(env.JWKS_URL ? { jwksUrl: env.JWKS_URL } : {}),
    ...extra,
    provider: providers,
  });
  if (!extra.replayStore && !extra.jwks) verifiers.set(key, v);
  return v;
}

/** Builds the Worker. `extra` lets tests inject keys, a clock or a replay store. */
export function createWorker(extra: WorkerOptions = {}) {
  return {
    async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
      // Fail closed before anything else: without a provider id nothing is forwarded.
      const providers = providerIds(env);
      if (providers.length === 0) {
        return misconfigured("ASSAY_PROVIDER_ID is not set: set it to your Assay provider id (shown in the portal)");
      }
      let verify: Verify;
      try {
        verify = verifierFor(env, providers, extra);
      } catch {
        // The value is not echoed: this answer goes to whoever called the Worker.
        return misconfigured("ASSAY_PROVIDER_ID is invalid: use your Assay provider id (shown in the portal); separate several with commas");
      }

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
      let result: Awaited<ReturnType<Verify>>;
      try {
        result = await verify({
          method: request.method,
          url: request.url,
          headers: authorityHeaders,
          body: hasBody ? bytes : null,
        });
      } catch (e) {
        // Fail closed: without a working replay store the request is not forwarded.
        if (e instanceof ReplayStoreUnavailableError) return json(503, '{"error":"replay_store_unavailable"}');
        throw e;
      }
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
 * Worker instances. It uses the SQLite storage backend (declared under
 * `new_sqlite_classes`); expired rows are removed by an alarm in one statement.
 */
export class NonceStore implements DurableObject {
  private readonly sql: SqlStorage;

  constructor(private readonly ctx: DurableObjectState, _env?: unknown) {
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, exp INTEGER NOT NULL)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS nonces_exp ON nonces (exp)");
  }

  async fetch(request: Request): Promise<Response> {
    let nonce: unknown;
    let ttlSeconds: unknown;
    try {
      ({ nonce, ttlSeconds } = (await request.json()) as { nonce: unknown; ttlSeconds: unknown });
    } catch {
      return Response.json({ error: "bad_request" }, { status: 400 });
    }
    if (typeof nonce !== "string" || nonce === "" || typeof ttlSeconds !== "number" || !Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      return Response.json({ error: "bad_request" }, { status: 400 });
    }
    const now = Date.now();
    const exp = now + Math.ceil(ttlSeconds * 1000);
    // Insert the nonce; a live row means "seen". A row that expired but was not yet
    // swept by the alarm is overwritten. RETURNING yields a row only when we wrote.
    const written = this.sql
      .exec(
        "INSERT INTO nonces (nonce, exp) VALUES (?, ?) ON CONFLICT (nonce) DO UPDATE SET exp = excluded.exp WHERE nonces.exp <= ? RETURNING nonce",
        nonce,
        exp,
        now,
      )
      .toArray().length;
    if (written === 0) return Response.json({ seen: true });
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || alarm > exp) await this.ctx.storage.setAlarm(exp);
    return Response.json({ seen: false });
  }

  async alarm(): Promise<void> {
    this.sql.exec("DELETE FROM nonces WHERE exp <= ?", Date.now());
    const next = this.sql.exec<{ next: number | null }>("SELECT MIN(exp) AS next FROM nonces").one().next;
    if (next !== null) await this.ctx.storage.setAlarm(next);
  }
}
