import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { createVerifier, type VerifyInput } from "../src/index.js";

const v1 = JSON.parse(readFileSync(new URL("../../test-vectors/v1.json", import.meta.url), "utf8"));
const te = new TextEncoder();
const [c1, c2] = v1.cases;

function inputOf(c: any): VerifyInput {
  return { method: c.request.method, url: c.request.url, headers: { ...c.request.headers, ...c.expected.headers }, body: c.request.body === undefined ? null : te.encode(c.request.body) };
}

function fakeFetch(keys: unknown[] = [v1.publicKeyJwk]) {
  return vi.fn(async (_url: string | URL | Request) => new Response(JSON.stringify({ keys }), { status: 200 }));
}

describe("JWKS cache", () => {
  it("fetches once for two verifications", async () => {
    const f = fakeFetch();
    let now = c1.params.created;
    const verify = createVerifier({ fetch: f as any, now: () => now });
    expect((await verify(inputOf(c1))).ok).toBe(true);
    now = c2.params.created;
    expect((await verify(inputOf(c2))).ok).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
    expect(f.mock.calls[0]![0]).toBe("https://api.goassay.ai/.well-known/assay-request-keys.json");
  });

  it("shares one JWKS cache per URL across verifiers", async () => {
    const f = fakeFetch();
    const opts = { fetch: f as any, jwksUrl: "https://shared.example.test/jwks.json", now: () => c1.params.created };
    expect((await createVerifier(opts)(inputOf(c1))).ok).toBe(true);
    expect((await createVerifier({ ...opts })(inputOf(c2))).ok).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("keeps a separate in-memory replay store per verifier when none is given", async () => {
    const opts = { jwks: { keys: [v1.publicKeyJwk] }, now: () => c1.params.created };
    expect((await createVerifier(opts)(inputOf(c1))).ok).toBe(true);
    expect((await createVerifier(opts)(inputOf(c1))).ok).toBe(true);
  });

  it("refetches once on unknown kid, then not again within 60s", async () => {
    const f = fakeFetch();
    let now = c1.params.created;
    const verify = createVerifier({ fetch: f as any, now: () => now });
    await verify(inputOf(c1));
    const sigIn = c1.expected.headers["Signature-Input"].replace(v1.keyId, "other-kid");
    const unknown = { ...inputOf(c1), headers: { ...inputOf(c1).headers as object, "Signature-Input": sigIn } };
    now += 61;
    expect(await verify(unknown)).toEqual({ ok: false, reason: "UNKNOWN_KEY" });
    expect(f).toHaveBeenCalledTimes(2);
    now += 30;
    await verify(unknown);
    expect(f).toHaveBeenCalledTimes(2);
    now += 31;
    await verify(unknown);
    expect(f).toHaveBeenCalledTimes(3);
  });

  it("fetch failure gives UNKNOWN_KEY and recovers later", async () => {
    let fail = true;
    let now = c1.params.created;
    const f = vi.fn(async () => { if (fail) throw new Error("down"); return new Response(JSON.stringify({ keys: [v1.publicKeyJwk] })); });
    const verify = createVerifier({ fetch: f as any, now: () => now });
    expect(await verify(inputOf(c1))).toEqual({ ok: false, reason: "UNKNOWN_KEY" });
    fail = false;
    expect(await verify(inputOf(c1))).toEqual({ ok: false, reason: "UNKNOWN_KEY" }); // inside 5s backoff
    expect(f).toHaveBeenCalledTimes(1);
    now += 6;
    expect((await verify(inputOf(c1))).ok).toBe(true);
  });

  it("uses the testnet URL for environment testnet", async () => {
    const f = fakeFetch();
    await createVerifier({ fetch: f as any, environment: "testnet", now: () => c1.params.created })(inputOf(c1));
    expect(f.mock.calls[0]![0]).toBe("https://api-dev.goassay.ai/.well-known/assay-request-keys.json");
  });

  it("explicit jwksUrl wins over environment", async () => {
    const f = fakeFetch();
    await createVerifier({ fetch: f as any, environment: "testnet", jwksUrl: "https://keys.example.test/jwks.json", now: () => c1.params.created })(inputOf(c1));
    expect(f.mock.calls[0]![0]).toBe("https://keys.example.test/jwks.json");
  });
});
