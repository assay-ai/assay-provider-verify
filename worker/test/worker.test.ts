import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryReplayStore } from "@assay-ai/provider-verify";
import { NonceStore, createWorker, durableReplayStore, type Env } from "../src/index.js";

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

describe("NonceStore", () => {
  function fakeState() {
    const m = new Map<string, number>();
    let alarm: number | null = null;
    return {
      m,
      getAlarm: () => alarm,
      state: {
        storage: {
          get: async (k: string) => m.get(k),
          put: async (k: string, v: number) => void m.set(k, v),
          delete: async (ks: string[]) => void ks.forEach((k) => m.delete(k)),
          list: async () => new Map(m),
          getAlarm: async () => alarm,
          setAlarm: async (t: number) => void (alarm = t),
        },
      } as unknown as DurableObjectState,
    };
  }
  const call = (o: NonceStore, nonce: string) =>
    o.fetch(new Request("https://x/", { method: "POST", body: JSON.stringify({ nonce, ttlSeconds: 60 }) })).then((r) => r.json());

  it("flags the second sighting and expires entries on alarm", async () => {
    const f = fakeState();
    const o = new NonceStore(f.state);
    expect(await call(o, "n1")).toEqual({ seen: false });
    expect(await call(o, "n1")).toEqual({ seen: true });
    expect(f.getAlarm()).not.toBeNull();
    f.m.set("n1", Date.now() - 1);
    await o.alarm();
    expect(f.m.size).toBe(0);
    expect(await call(o, "n1")).toEqual({ seen: false });
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
