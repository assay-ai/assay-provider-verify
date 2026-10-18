# How Assay protects your API

Assay can prove to your API that a request really came from Assay. There are two modes. You can use one or both.

## Choose a mode

| | API-key mode | Signature mode |
|---|---|---|
| Code to write | None | A verifier (levels 0, 1 or 2 below) |
| What proves the caller | A secret key you set in Assay | An Ed25519 signature on every request |
| If the key leaks | Anyone can call you | Nothing leaks. You hold only public keys. |
| Protects the body | No | Yes (digest in the signature) |
| Stops replays | No | Yes (one-time numbers) |

Start with API-key mode if you want to be live today. Move to signature mode when you can. It is safer and not hard.

### API-key mode (no code)

You choose a secret key and enter it in Assay. Assay sends it in a request header on every call. Your API (or your gateway) checks the header and rejects requests without the right value. Most API gateways can do this with a setting, not code.

- Keys go **only in headers**. Never put a key in the URL or the query string. URLs end up in logs, browser history and error reports.
- Use a long random value, and rotate it if you think it leaked.
- Check it with a constant-time comparison if you check it in code.

### Signature mode

Assay signs every request. You verify the signature with Assay's public keys. Pick the level that fits you:

| Level | What you do | Page |
|---|---|---|
| 0 | Deploy a Cloudflare Worker in front of your API. No code. | [level-0-cloudflare-worker.md](level-0-cloudflare-worker.md) |
| 1 | Add a few lines of middleware (Node, Python, Go). | [level-1-node.md](level-1-node.md), [level-1-python.md](level-1-python.md), [level-1-go.md](level-1-go.md) |
| 2 | Write the check yourself, in any language. | [level-2-manual.md](level-2-manual.md) |

If something is rejected, see [troubleshooting.md](troubleshooting.md).

The rest of this page is the full contract. You only need it for level 2 or if you are curious.

## How a signed request looks

Every request Assay sends to your API carries two headers, `Signature-Input` and `Signature` (label `assay`), and a `Content-Digest` header when the request has a body. Verifying them proves the request came from Assay and was not altered. This page is the full contract, so you can also write your own verifier.

## Where to get the public keys

- production: `https://api.goassay.ai/.well-known/assay-request-keys.json`
- testnet: `https://api-dev.goassay.ai/.well-known/assay-request-keys.json`

The file is a JWKS with Ed25519 keys (`kty: "OKP"`, `crv: "Ed25519"`). Match the `keyid` parameter to the key's `kid`. Cache the file for one hour; on an unknown `kid`, refetch at most once per 60 seconds.

## Signature format

- Components, in this order: `"@method" "@authority" "@path" "@query"`, then `"content-digest"` only when the request has a body, then `"x-assay-call-id"`.
- `@method` is uppercase. `@authority` is the lowercase host, with `:port` only when the port is not the scheme default. `@path` is the path as sent (`/` if empty). `@query` is `?` plus the query, or `?` alone when there is none.
- `Content-Digest: sha-256=:<base64 of SHA-256 over the raw body bytes>:`
- Parameters, in this order: `created`, `expires` (created + 300), `nonce`, `keyid`, `alg="ed25519"`, `tag="assay-request"`.
- Signature base: one line per component, `"<name>": <value>`, then the last line `"@signature-params": <inner list><params>`. Lines are joined with `\n`, no trailing newline.
- Headers: `Signature-Input: assay=<inner list><params>` and `Signature: assay=:<base64 signature>:`.

## Verification steps

1. Read `Signature-Input` and `Signature`, member `assay`. Missing: `MISSING`. Unparsable: `MALFORMED`.
2. Check `tag="assay-request"` (else `WRONG_TAG`), `alg="ed25519"`, integer `created` and `expires`, non-empty `nonce` and `keyid` (else `MALFORMED`).
3. The covered components must be exactly the list above. A non-empty body whose `content-digest` is not covered: `MALFORMED`. When covered, recompute the digest over the raw body and compare with the header: mismatch is `DIGEST_MISMATCH`.
4. Time: `created - 60 <= now <= expires + 60` and `expires - created <= 300`, else `EXPIRED`.
5. Rebuild the signature base from the received request. `@authority` is the `Host` header as received (lowercased; the SDKs never add or strip a port), unless you configure an override (for example behind a proxy that rewrites Host or the port).
6. Find `keyid` in the JWKS (else `UNKNOWN_KEY`) and verify the Ed25519 signature (else `BAD_SIGNATURE`).
7. Nonce: if already seen, `REPLAYED`; otherwise remember it until `expires + 60`.

Reject with `401`, `content-type: application/json`, body `{"error":"invalid_assay_signature","reason":"<CODE>"}`.

## Reason codes

`MISSING`, `MALFORMED`, `WRONG_TAG`, `DIGEST_MISMATCH`, `EXPIRED`, `UNKNOWN_KEY`, `BAD_SIGNATURE`, `REPLAYED`.

## Test vectors

Both files hold a public test key (`publicKeyJwk`, `keyId`). The seed in `v1.json` is public and for tests only, never use it elsewhere.

- `test-vectors/v1.json`: valid requests with the expected signature base and headers. Rebuilding the base from `request` and `params` must give `expected.signatureBase`; the headers must verify.
- `test-vectors/negative.json`: requests that must be rejected. Its `format` field repeats the rules below.

Negative file shape: each case runs against a fresh verifier (empty nonce store) configured with `publicKeyJwk`. A case with `request` is verified once at unix time `now` and must give `expectedReason` (`"OK"` means accepted). A case with `sequence` is a list of steps `{request, now, expectedReason}` verified in order against the same verifier; this is how replay is expressed. Header names are lowercase, `host` is the Host header, `body` is a UTF-8 string and absent when there is no body. Regenerate with `node scripts/make-negative-vectors.mjs` (deterministic, `node:crypto` only).

| Case | Expected | Why |
|---|---|---|
| body-changed | DIGEST_MISMATCH | Body altered, original `Content-Digest` and signature kept. |
| host-changed | BAD_SIGNATURE | Host altered, so the rebuilt base differs from the signed one. |
| wrong-tag | WRONG_TAG | Correctly signed, but `tag="other"`. |
| expired | EXPIRED | Correctly signed; `now = expires + 61`. |
| clock-skew-accepted | OK | Correctly signed; `now = created - 59`, within the 60 s skew. |
| unknown-key | UNKNOWN_KEY | Correctly signed, but `keyid` is not in the JWKS. |
| replay | OK then REPLAYED | Same request twice; the second reuses the nonce. |
| body-without-content-digest | MALFORMED | Correctly signed POST with a body, `content-digest` not covered. |
| signature-headers-missing | MISSING | No `Signature` or `Signature-Input`. |
