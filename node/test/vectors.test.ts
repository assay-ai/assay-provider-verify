import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createVerifier, type VerifyInput } from "../src/index.js";

const load = (n: string) => JSON.parse(readFileSync(new URL(`../../test-vectors/${n}`, import.meta.url), "utf8"));
const v1 = load("v1.json");
const neg = load("negative.json");
const te = new TextEncoder();

function toInput(r: { method: string; url: string; headers: Record<string, string>; body?: string }, extra: Record<string, string> = {}): VerifyInput {
  return { method: r.method, url: r.url, headers: { ...r.headers, ...extra }, body: r.body === undefined ? null : te.encode(r.body) };
}

describe("positive vectors", () => {
  for (const c of v1.cases) {
    it(c.name, async () => {
      const verify = createVerifier({ jwks: { keys: [v1.publicKeyJwk] }, now: () => c.params.created });
      const res = await verify(toInput(c.request, c.expected.headers));
      expect(res).toMatchObject({ ok: true, keyId: v1.keyId });
    });
  }
});

describe("negative vectors", () => {
  for (const c of neg.cases) {
    it(c.name, async () => {
      const steps = c.sequence ?? [{ request: c.request, now: c.now, expectedReason: c.expectedReason }];
      let now = 0;
      const verify = createVerifier({ jwks: { keys: [neg.publicKeyJwk] }, now: () => now });
      for (const s of steps) {
        now = s.now;
        const res = await verify(toInput(s.request));
        if (s.expectedReason === "OK") expect(res.ok).toBe(true);
        else expect(res).toEqual({ ok: false, reason: s.expectedReason });
      }
    });
  }
});
