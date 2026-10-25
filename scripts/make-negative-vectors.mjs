#!/usr/bin/env node
// Generates test-vectors/negative.json from the first case of test-vectors/v1.json.
// Deterministic: Ed25519 signatures are deterministic and nothing random or time-based is used.
// Uses only node:crypto. The seed is the TEST-ONLY seed published in v1.json.
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const v1 = JSON.parse(readFileSync(join(root, 'test-vectors', 'v1.json'), 'utf8'));
const base = v1.cases[0];
const { created, expires, nonce, audience } = base.params;
// Verifiers run with exactly this provider id configured.
const provider = audience;

const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), // PKCS#8 prefix for Ed25519
    Buffer.from(v1.seedHex, 'hex'),
  ]),
  format: 'der',
  type: 'pkcs8',
});

const url = new URL(base.request.url);
const authority = url.host; // lowercased by URL; default port already dropped
const callId = base.request.headers['x-assay-call-id'];
const digestOf = (body) => `sha-256=:${createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64')}:`;

// Signs a request with the same format as the real signer; opts allow targeted deviations.
// aud: a string is sent quoted; null omits the parameter; any other value is written raw (e.g. an integer).
function signed({ method = 'POST', body, keyid = v1.keyId, tag = 'assay-request', aud = provider, coverDigest = body !== undefined, nonceValue = nonce, host = authority }) {
  const path = url.pathname || '/';
  const q = url.search ? url.search : '?';
  const comps = ['@method', '@authority', '@path', '@query'];
  const lines = [`"@method": ${method}`, `"@authority": ${authority}`, `"@path": ${path}`, `"@query": ${q}`];
  const headers = { host, 'x-assay-call-id': callId };
  if (coverDigest) {
    comps.push('content-digest');
    lines.push(`"content-digest": ${digestOf(body)}`);
  }
  if (body !== undefined) headers['content-digest'] = digestOf(body);
  comps.push('x-assay-call-id');
  lines.push(`"x-assay-call-id": ${callId}`);
  const inner = `(${comps.map((c) => `"${c}"`).join(' ')})`;
  const audParam = aud === null ? '' : typeof aud === 'string' ? `;aud="${aud}"` : `;aud=${aud}`;
  const params = `;created=${created};expires=${expires};nonce="${nonceValue}";keyid="${keyid}";alg="ed25519";tag="${tag}"${audParam}`;
  lines.push(`"@signature-params": ${inner}${params}`);
  const sig = sign(null, Buffer.from(lines.join('\n'), 'utf8'), privateKey).toString('base64');
  headers['signature-input'] = `assay=${inner}${params}`;
  headers['signature'] = `assay=:${sig}:`;
  const request = { method, url: `https://${authority}${url.pathname}${url.search}`, headers };
  if (body !== undefined) request.body = body;
  return request;
}

const body = base.request.body;
const good = signed({ body });
const inside = created + 10;
const copy = (o) => JSON.parse(JSON.stringify(o));

const cases = [];
cases.push({
  name: 'body-changed',
  why: 'Body differs from the signed one while Content-Digest and signature are unchanged; the recomputed digest does not match.',
  request: { ...copy(good), body: '{"q":"tampered"}' },
  now: inside,
  expectedReason: 'DIGEST_MISMATCH',
});
cases.push({
  name: 'host-changed',
  why: 'Host header differs from the signed authority; the rebuilt signature base differs, so the signature does not verify.',
  request: { ...copy(good), headers: { ...good.headers, host: 'other.example.test' } },
  now: inside,
  expectedReason: 'BAD_SIGNATURE',
});
cases.push({
  name: 'wrong-tag',
  why: 'Validly signed, but tag is "other" instead of "assay-request".',
  request: signed({ body, tag: 'other' }),
  now: inside,
  expectedReason: 'WRONG_TAG',
});
cases.push({
  name: 'expired',
  why: 'Validly signed; now = expires + 61, which is beyond the 60 s skew allowance.',
  request: copy(good),
  now: expires + 61,
  expectedReason: 'EXPIRED',
});
cases.push({
  name: 'clock-skew-accepted',
  why: 'Validly signed; now = created - 59, inside the 60 s skew allowance, so it is accepted.',
  request: copy(good),
  now: created - 59,
  expectedReason: 'OK',
});
cases.push({
  name: 'unknown-key',
  why: 'Validly signed with the test seed, but keyid "unknown-key" is not in the JWKS.',
  request: signed({ body, keyid: 'unknown-key' }),
  now: inside,
  expectedReason: 'UNKNOWN_KEY',
});
cases.push({
  name: 'replay',
  why: 'The same valid request is sent twice against one verifier instance; the first is accepted, the second reuses the nonce.',
  sequence: [
    { request: copy(good), now: inside, expectedReason: 'OK' },
    { request: copy(good), now: inside + 1, expectedReason: 'REPLAYED' },
  ],
  expectedReason: 'REPLAYED',
});
cases.push({
  name: 'body-without-content-digest',
  why: 'Validly signed POST with a body, but content-digest is not among the covered components.',
  request: signed({ body, coverDigest: false }),
  now: inside,
  expectedReason: 'MALFORMED',
});
{
  const r = copy(good);
  delete r.headers['signature'];
  delete r.headers['signature-input'];
  cases.push({
    name: 'signature-headers-missing',
    why: 'Neither Signature nor Signature-Input is present.',
    request: r,
    now: inside,
    expectedReason: 'MISSING',
  });
}

cases.push({
  name: 'wrong-provider',
  why: 'Validly signed by Assay, but for another provider (aud "prov-other"); the configured provider is the one in "provider".',
  request: signed({ body, aud: 'prov-other' }),
  now: inside,
  expectedReason: 'WRONG_PROVIDER',
});
cases.push({
  name: 'audience-missing',
  why: 'Validly signed, but Signature-Input has no aud parameter (an old-format signature).',
  request: signed({ body, aud: null }),
  now: inside,
  expectedReason: 'WRONG_PROVIDER',
});
cases.push({
  name: 'audience-not-string',
  why: 'Validly signed, but aud is the integer 1 instead of a string.',
  request: signed({ body, aud: 1 }),
  now: inside,
  expectedReason: 'WRONG_PROVIDER',
});
{
  const r = signed({ body, aud: 'prov-other' });
  r.headers['signature-input'] = r.headers['signature-input'].replace('aud="prov-other"', `aud="${provider}"`);
  cases.push({
    name: 'audience-changed',
    why: 'Signed for "prov-other", then aud in Signature-Input was rewritten to the configured provider; the signature covers the parameters, so it does not verify.',
    request: r,
    now: inside,
    expectedReason: 'BAD_SIGNATURE',
  });
}

const out = {
  format:
    'Each case runs against a FRESH verifier (empty nonce store) configured with publicKeyJwk below and with exactly one provider id, "provider" below. A case with "request" is verified once at unix time "now" and must give "expectedReason" ("OK" = accepted). A case with "sequence" is a list of steps verified in order against the same verifier; each step has request, now and expectedReason. Header names in request.headers are lowercase; host is the value of the Host header and is used as @authority. body is a UTF-8 string and absent when the request has no body.',
  keyId: v1.keyId,
  provider,
  publicKeyJwk: v1.publicKeyJwk,
  cases,
};
writeFileSync(join(root, 'test-vectors', 'negative.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${cases.length} cases`);
