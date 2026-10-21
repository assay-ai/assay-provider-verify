import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyAssayRequest, createVerifier, type VerifyInput } from "../src/index.js";
import { JwksCache } from "../src/jwks.js";

const v1 = JSON.parse(readFileSync(new URL("../../test-vectors/v1.json", import.meta.url), "utf8"));
const te = new TextEncoder();
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const c1 = v1.cases[0];
const inputOf = (c: any): VerifyInput => ({ method: c.request.method, url: c.request.url, headers: { ...c.request.headers, ...c.expected.headers }, body: c.request.body === undefined ? null : te.encode(c.request.body) });

afterEach(() => vi.useRealTimers());

describe("I1 one-shot helper shares state", () => {
  it("second call with fresh options objects is REPLAYED", async () => {
    const mk = () => ({ jwks: { keys: [v1.publicKeyJwk] }, now: () => c1.params.created });
    expect((await verifyAssayRequest(inputOf(c1), mk())).ok).toBe(true);
    expect(await verifyAssayRequest(inputOf(c1), mk())).toEqual({ ok: false, reason: "REPLAYED" });
  });
  it("fetches JWKS once across fresh options objects", async () => {
    const f = vi.fn(async () => new Response(JSON.stringify({ keys: [v1.publicKeyJwk] })));
    const c2 = v1.cases[1];
    await verifyAssayRequest(inputOf(c2), { fetch: f as any, now: () => c2.params.created });
    await verifyAssayRequest(inputOf(c2), { fetch: f as any, now: () => c2.params.created });
    expect(f).toHaveBeenCalledTimes(1);
  });
});

describe("I2 concurrent getKey", () => {
  it("static keys", async () => {
    const cache = new JwksCache({ jwks: { keys: [v1.publicKeyJwk] } });
    const r = await Promise.all([cache.getKey(v1.keyId, 1), cache.getKey(v1.keyId, 1)]);
    expect(r.every(Boolean)).toBe(true);
  });
  it("fetched keys", async () => {
    const f = vi.fn(async () => { await new Promise((r) => setTimeout(r, 10)); return new Response(JSON.stringify({ keys: [v1.publicKeyJwk] })); });
    const cache = new JwksCache({ fetch: f as any });
    const r = await Promise.all([cache.getKey(v1.keyId, 1), cache.getKey(v1.keyId, 1)]);
    expect(r.every(Boolean)).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
  });
});

describe("H1 request target", () => {
  const verify = () => createVerifier({ jwks: { keys: [v1.publicKeyJwk] }, now: () => c1.params.created });
  it("rejects // targets", async () => {
    const i = { ...inputOf(c1), url: "//evil.test/v1/search?q=a%20b" };
    expect(await verify()(i)).toEqual({ ok: false, reason: "MALFORMED" });
  });
  it("uses path+query as sent for origin-form targets (needs Host)", async () => {
    const i = { ...inputOf(c1), url: "/v1/search?q=a%20b", headers: { ...(inputOf(c1).headers as object), host: "api.example.test" } };
    expect((await verify()(i)).ok).toBe(true);
  });
});

describe("H2 fetch timeout", () => {
  it("a hanging fetch is bounded at 5s and then UNKNOWN_KEY", async () => {
    vi.useFakeTimers();
    try {
      const f = vi.fn(() => new Promise<Response>(() => {}));
      const verify = createVerifier({ fetch: f as any, now: () => c1.params.created });
      const p = verify(inputOf(c1));
      // The timeout is armed only once the request reaches the fetch, after
      // real (unfaked) crypto work: advancing before that would skip it.
      await vi.waitFor(() => expect(f).toHaveBeenCalled());
      await vi.advanceTimersByTimeAsync(5001);
      expect(await p).toEqual({ ok: false, reason: "UNKNOWN_KEY" });
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("H3 expires < created", () => {
  it("is EXPIRED", async () => {
    const d = Buffer.from(v1.seedHex, "hex");
    const key = await crypto.subtle.importKey("jwk", { ...v1.publicKeyJwk, d: b64u(d), key_ops: ["sign"], use: undefined, alg: undefined }, { name: "Ed25519" }, false, ["sign"]);
    const created = c1.params.created;
    const params = `created=${created};expires=${created - 10};nonce="AQEBAQEBAQEBAQEBAQEBAQ";keyid="${v1.keyId}";alg="ed25519";tag="assay-request"`;
    const list = `("@method" "@authority" "@path" "@query" "content-digest" "x-assay-call-id")`;
    const base = [`"@method": POST`, `"@authority": api.example.test`, `"@path": /v1/search`, `"@query": ?q=a%20b`, `"content-digest": ${c1.expected.headers["Content-Digest"]}`, `"x-assay-call-id": c-1`, `"@signature-params": ${list};${params}`].join("\n");
    const sig = Buffer.from(await crypto.subtle.sign("Ed25519", key, te.encode(base))).toString("base64");
    const i = inputOf(c1);
    i.headers = { ...(i.headers as object), "Signature-Input": `assay=${list};${params}`, Signature: `assay=:${sig}:` };
    const res = await createVerifier({ jwks: { keys: [v1.publicKeyJwk] }, now: () => created })(i);
    expect(res).toEqual({ ok: false, reason: "EXPIRED" });
  });
});
