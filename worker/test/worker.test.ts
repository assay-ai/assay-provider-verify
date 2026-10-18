import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryReplayStore } from "@assay-ai/provider-verify";
import { DatabaseSync } from "node:sqlite";
import { NonceStore, ReplayStoreUnavailableError, createWorker, durableReplayStore, type Env } from "../src/index.js";

const v1 = JSON.parse(readFileSync(new URL("../../test-vectors/v1.json", import.meta.url), "utf8"));
const c = v1.cases[0];
const env: Env = { ORIGIN_URL: "https://origin.example.com" };

function opts() {
  return { jwks: { keys: [v1.publicKeyJwk] }, now: () => c.params.created, replayStore: new MemoryReplayStore() };
}
function signed(body: string = c.request.body): Request {
  return new Request(c.request.url, {
    method: c.request.method,
    headers: { ...c.request.headers, ...c.expected.headers },
    body,
  });
}
const originFetch = vi.fn(async (..._a: unknown[]) => new Response("ok", { status: 200 }));
vi.stubGlobal("fetch", originFetch);
afterEach(() => originFetch.mockClear());

describe("worker", () => {
  it("forwards a valid request once, without signature headers", async () => {
    const res = await createWorker(opts()).fetch(signed(), env);
    expect(res.status).toBe(200);
    expect(originFetch).toHaveBeenCalledTimes(1);
    const [url, init] = originFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://origin.example.com/v1/search?q=a%20b");
    const h = new Headers(init.headers);
    for (const n of ["signature", "signature-input", "content-digest", "host"]) expect(h.has(n)).toBe(false);
    expect(h.get("x-assay-call-id")).toBe("c-1");
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("manual");
    expect(new TextDecoder().decode(init.body as Uint8Array)).toBe(c.request.body);
  });

  it("rejects a tampered request with 401 and no origin call", async () => {
    const res = await createWorker(opts()).fetch(signed('{"q":"evil"}'), env);
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await res.text()).toBe('{"error":"invalid_assay_signature","reason":"DIGEST_MISMATCH"}');
    expect(originFetch).not.toHaveBeenCalled();
  });

  it("rejects an unsigned request", async () => {
    const res = await createWorker(opts()).fetch(new Request("https://api.example.test/x"), env);
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('"reason":"MISSING"');
    expect(originFetch).not.toHaveBeenCalled();
  });

  it("answers 413 for an oversized declared body before verifying", async () => {
    const req = new Request("https://api.example.test/x", { method: "POST", headers: { "content-length": "6000000" }, body: "x" });
    const res = await createWorker(opts()).fetch(req, env);
    expect(res.status).toBe(413);
    expect(await res.text()).toBe('{"error":"payload_too_large"}');
  });

  it("detects a replay through the NonceStore binding", async () => {
    const seen = new Set<string>();
    const ns = {
      idFromName: (n: string) => n,
      get: () => ({
        fetch: async (_u: string, init: { body: string }) => {
          const { nonce } = JSON.parse(init.body);
          const dup = seen.has(nonce);
          seen.add(nonce);
          return Response.json({ seen: dup });
        },
      }),
    } as unknown as DurableObjectNamespace;
    const w = createWorker({ jwks: { keys: [v1.publicKeyJwk] }, now: () => c.params.created });
    const e = { ...env, NONCE_STORE: ns };
    expect((await w.fetch(signed(), e)).status).toBe(200);
    const replay = await w.fetch(signed(), e);
    expect(replay.status).toBe(401);
    expect(await replay.text()).toContain('"reason":"REPLAYED"');
    expect(originFetch).toHaveBeenCalledTimes(1);
  });

  it("adds the optional origin secret header", async () => {
    await createWorker(opts()).fetch(signed(), { ...env, ORIGIN_SECRET: "s3" });
    const init = originFetch.mock.calls[0]![1] as RequestInit;
    expect(new Headers(init.headers).get("x-assay-origin-secret")).toBe("s3");
  });

  it("does not follow redirects for the caller", async () => {
    originFetch.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: "https://x.test/" } }));
    const res = await createWorker(opts()).fetch(signed(), env);
    expect(res.status).toBe(302);
  });
});

describe("durable replay store fails closed", () => {
  const nsAnswering = (answer: () => Promise<Response>) =>
    ({ idFromName: (n: string) => n, get: () => ({ fetch: answer }) }) as unknown as DurableObjectNamespace;
  const w = () => createWorker({ jwks: { keys: [v1.publicKeyJwk] }, now: () => c.params.created });

  it("answers 503 when the Durable Object returns an error status", async () => {
    const res = await w().fetch(signed(), { ...env, NONCE_STORE: nsAnswering(async () => new Response("boom", { status: 500 })) });
    expect(res.status).toBe(503);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await res.text()).toBe('{"error":"replay_store_unavailable"}');
    expect(originFetch).not.toHaveBeenCalled();
  });

  it("answers 503 when the Durable Object call throws", async () => {
    const res = await w().fetch(signed(), {
      ...env,
      NONCE_STORE: nsAnswering(async () => {
        throw new Error("Durable Object reset");
      }),
    });
    expect(res.status).toBe(503);
    expect(originFetch).not.toHaveBeenCalled();
  });

  it("durableReplayStore throws ReplayStoreUnavailableError on a non-ok answer or a bad body", async () => {
    await expect(durableReplayStore(nsAnswering(async () => new Response("", { status: 503 }))).checkAndStore("a", 60)).rejects.toBeInstanceOf(
      ReplayStoreUnavailableError,
    );
    await expect(durableReplayStore(nsAnswering(async () => Response.json({}))).checkAndStore("a", 60)).rejects.toBeInstanceOf(
      ReplayStoreUnavailableError,
    );
  });
});

describe("NonceStore", () => {
  /**
   * Fake DurableObjectState exposing only what NonceStore may use: `storage.sql.exec`
   * (backed by a real SQLite database, with the Cloudflare cursor's `toArray`/`one`)
   * and the alarm methods. `node:sqlite` needs Node >= 22.13 (see worker/package.json engines). Any other storage API (get/put/list/delete) is absent and throws.
   */
  function fakeState() {
    const db = new DatabaseSync(":memory:");
    let alarm: number | null = null;
    const statements: string[] = [];
    const sql = {
      exec(query: string, ...bindings: unknown[]) {
        statements.push(query);
        const rows = db.prepare(query).all(...(bindings as never[])) as Record<string, unknown>[];
        return {
          toArray: () => rows,
          one: () => {
            if (rows.length !== 1) throw new Error(`Expected exactly one result from SQL query, got ${rows.length}`);
            return rows[0];
          },
        };
      },
    };
    const storage = new Proxy(
      { sql, getAlarm: async () => alarm, setAlarm: async (t: number) => void (alarm = t) } as Record<string, unknown>,
      {
        get(target, prop) {
          if (typeof prop === "string" && !(prop in target)) throw new Error(`storage.${prop} is not allowed in the fake`);
          return target[prop as string];
        },
      },
    );
    return {
      db,
      statements,
      getAlarm: () => alarm,
      count: () => (db.prepare("SELECT COUNT(*) AS n FROM nonces").get() as { n: number }).n,
      state: { storage } as unknown as DurableObjectState,
    };
  }
  const call = (o: NonceStore, nonce: unknown, ttlSeconds: unknown = 60) =>
    o.fetch(new Request("https://x/", { method: "POST", body: JSON.stringify({ nonce, ttlSeconds }) }));

  it("flags the second sighting and expires entries on alarm", async () => {
    const f = fakeState();
    const o = new NonceStore(f.state);
    expect(await (await call(o, "n1")).json()).toEqual({ seen: false });
    expect(await (await call(o, "n1")).json()).toEqual({ seen: true });
    expect(f.getAlarm()).not.toBeNull();
    f.db.prepare("UPDATE nonces SET exp = ? WHERE nonce = 'n1'").run(Date.now() - 1);
    await o.alarm();
    expect(f.count()).toBe(0);
    expect(await (await call(o, "n1")).json()).toEqual({ seen: false });
  });

  it("treats an expired row the alarm has not swept yet as unseen", async () => {
    const f = fakeState();
    const o = new NonceStore(f.state);
    await call(o, "n2");
    f.db.prepare("UPDATE nonces SET exp = ? WHERE nonce = 'n2'").run(Date.now() - 1);
    expect(await (await call(o, "n2")).json()).toEqual({ seen: false });
    expect(await (await call(o, "n2")).json()).toEqual({ seen: true });
  });

  it("alarm deletes any number of expired rows in one statement and re-arms to the earliest live expiry", async () => {
    const f = fakeState();
    const o = new NonceStore(f.state);
    const ins = f.db.prepare("INSERT INTO nonces (nonce, exp) VALUES (?, ?)");
    const past = Date.now() - 1000;
    for (let i = 0; i < 1000; i++) ins.run(`old${i}`, past);
    const live = Date.now() + 120_000;
    ins.run("live-late", live + 5000);
    ins.run("live-early", live);
    f.statements.length = 0;
    await o.alarm();
    expect(f.count()).toBe(2);
    expect(f.getAlarm()).toBe(live);
    expect(f.statements.filter((q) => q.startsWith("DELETE"))).toHaveLength(1);
  });

  it("alarm leaves no alarm set when the table is empty", async () => {
    const f = fakeState();
    const o = new NonceStore(f.state);
    await o.alarm();
    expect(f.getAlarm()).toBeNull();
  });

  it("rejects malformed requests with 400", async () => {
    const o = new NonceStore(fakeState().state);
    expect((await call(o, "")).status).toBe(400);
    expect((await call(o, "n", "60")).status).toBe(400);
    expect((await o.fetch(new Request("https://x/", { method: "POST", body: "not json" }))).status).toBe(400);
  });

  it("durableReplayStore follows the ReplayStore contract", async () => {
    const o = new NonceStore(fakeState().state);
    const store = durableReplayStore({
      idFromName: (n: string) => n,
      get: () => ({ fetch: (u: string, i: RequestInit) => o.fetch(new Request(u, i)) }),
    } as unknown as DurableObjectNamespace);
    expect(await store.checkAndStore("a", 60)).toBe(true);
    expect(await store.checkAndStore("a", 60)).toBe(false);
  });
});
