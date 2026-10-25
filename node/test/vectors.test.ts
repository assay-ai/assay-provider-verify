import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createVerifier, verifyAssayRequest, type VerifyInput } from "../src/index.js";

const load = (n: string) => JSON.parse(readFileSync(new URL(`../../test-vectors/${n}`, import.meta.url), "utf8"));
const v1 = load("v1.json");
const neg = load("negative.json");
const te = new TextEncoder();

function toInput(r: { method: string; url: string; headers: Record<string, string>; body?: string }, extra: Record<string, string> = {}): VerifyInput {
  return { method: r.method, url: r.url, headers: { ...r.headers, ...extra }, body: r.body === undefined ? null : te.encode(r.body) };
}

const keys = { keys: [v1.publicKeyJwk] };

describe("positive vectors", () => {
  for (const c of v1.cases) {
    it(c.name, async () => {
      const verify = createVerifier({ provider: c.params.audience, jwks: keys, now: () => c.params.created });
      const res = await verify(toInput(c.request, c.expected.headers));
      expect(res).toMatchObject({ ok: true, keyId: v1.keyId, callId: "c-1", providerId: c.params.audience });
    });
    it(`${c.name}: a list containing the provider passes`, async () => {
      const verify = createVerifier({ provider: ["prov-other", c.params.audience], jwks: keys, now: () => c.params.created });
      expect(await verify(toInput(c.request, c.expected.headers))).toMatchObject({ ok: true, providerId: c.params.audience });
    });
    it(`${c.name}: another provider is WRONG_PROVIDER`, async () => {
      const verify = createVerifier({ provider: ["prov-other", "prov-test-2"], jwks: keys, now: () => c.params.created });
      expect(await verify(toInput(c.request, c.expected.headers))).toEqual({ ok: false, reason: "WRONG_PROVIDER" });
    });
  }
});

describe("provider option", () => {
  const bad: unknown[] = [undefined, "", [], [""], ["ok", 1], "has space", "a,b", "x".repeat(129)];
  for (const provider of bad) {
    it(`createVerifier throws for ${JSON.stringify(provider)}`, () => {
      expect(() => createVerifier({ provider, jwks: keys } as never)).toThrow(TypeError);
    });
  }
  it("createVerifier throws without options", () => {
    expect(() => (createVerifier as (o?: unknown) => unknown)()).toThrow(/provider/);
  });
  it("verifyAssayRequest throws without provider", () => {
    const c = v1.cases[0];
    expect(() => verifyAssayRequest(toInput(c.request, c.expected.headers), { jwks: keys } as never)).toThrow(/provider/);
  });
});

describe("negative vectors", () => {
  for (const c of neg.cases) {
    it(c.name, async () => {
      const steps = c.sequence ?? [{ request: c.request, now: c.now, expectedReason: c.expectedReason }];
      let now = 0;
      const verify = createVerifier({ provider: neg.provider, jwks: { keys: [neg.publicKeyJwk] }, now: () => now });
      for (const s of steps) {
        now = s.now;
        const res = await verify(toInput(s.request));
        if (s.expectedReason === "OK") expect(res.ok).toBe(true);
        else expect(res).toEqual({ ok: false, reason: s.expectedReason });
      }
    });
  }
});
