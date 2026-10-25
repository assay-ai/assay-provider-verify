# Troubleshooting

When a request is rejected, the `401` body tells you why:

```json
{"error":"invalid_assay_signature","reason":"BAD_SIGNATURE"}
```

Find the reason below. If your own logs show only "401", log the `reason` field first.

## BAD_SIGNATURE

The signature does not match what your server rebuilt. The signature covers the method, the host, the path, the query and the call id. If anything in front of your app changes one of them, the check fails.

Likely causes and fixes:

- **A proxy or load balancer rewrites `Host`.** Your app sees an internal name or port, but Assay signed the public one. The SDKs use the `Host` header exactly as received (lowercased) and never add or strip a port. Set the `authority` option to the public host, for example `authority: "api.example.com"`. Add the port only if it is not the scheme default.
- **Dot segments in the path with Hono, Next.js or the Cloudflare Worker.** These run on the WHATWG `Request` URL, which is already normalised: `/a/./b` and `/a/../b` arrive as `/a/b` and `/b`, so the rebuilt `@path` differs from the signed one. Express, Fastify, Python and Go see the target as sent. Register endpoint URLs without `.` or `..` segments.
- **A proxy rewrites the path or the query.** Examples: stripping a prefix, adding a trailing slash, re-encoding `%20` as `+`. Verify before the rewrite, or stop rewriting. Do not change paths on the way to the verifier.
- **Your framework decodes the path or query** before you read it. Give the verifier the target exactly as sent.
- **You are using the wrong key set** for the traffic. That normally gives `UNKNOWN_KEY` first, but check the environment anyway.
- **A redirect.** See below.

## My endpoint redirects

The endpoint Assay calls must **not redirect**. This includes redirects to the same site, such as `http` to `https`, a missing trailing slash, or `www` to the bare domain.

When a client follows a redirect, it sends the signature from the first request to the new address. The signed host, path or query no longer match, so the verifier rejects it with `BAD_SIGNATURE`. If the first request was already counted, the retry may also show up as `REPLAYED`.

Fix: register the final URL in Assay (the exact scheme, host and path), and make sure that URL answers directly.

## DIGEST_MISMATCH

The body your verifier hashed is not the body Assay sent.

Likely causes and fixes:

- **The body was parsed before verifying.** A JSON parser that runs first and then re-serialises the data changes spaces, key order or number formats. Mount the verifier before any body parser, or give it the raw bytes.
- **Express:** the middleware answers `500` with "mount assayVerify() before body parsers" when a parser already ran. Move `app.use(assayVerify())` above `express.json()`.
- **A proxy changes the body.** Compression, character set conversion or "pretty printing" gateways change the bytes. Turn them off for this route.
- **The body was read twice** and the second read was empty. Buffer it once.

## EXPIRED

The request is outside its time window. The window is the time between `created` and `expires`, with 60 seconds of tolerance on both sides.

Likely causes and fixes:

- **Your server clock is wrong.** Turn on NTP time sync (on Linux, `timedatectl set-ntp true`). Check the time with `date -u`.
- **The request was delayed.** A queue or a slow retry can hold it for more than 6 minutes. Call your API directly, not through a queue.
- **You pinned the time in tests** (the `now` option) and left it on. Remove it in production.

## REPLAYED

The same signed request was seen twice. Each request has a one-time number (nonce), and your verifier remembers the ones it has seen.

Likely causes and fixes:

- **Retries.** If your gateway or client retries a request, the retry carries the old signature. Do not retry at the proxy level. A retry must be signed again.
- **Several instances without a shared store.** The default store is in memory and belongs to one process. That alone does not cause `REPLAYED`, but it means a replayed request can slip through on another instance. Use a shared replay store such as Redis. For Node see [level-1-node.md](level-1-node.md#multiple-instances-and-redis). For Python see the Redis section of [level-1-python.md](level-1-python.md).
- **A redirect.** See above.
- **Your tests send the same fixture twice.** Use a fresh store per test, or a new nonce.

## UNKNOWN_KEY

The `keyid` in the request is not in the key set your verifier has.

Likely causes and fixes:

- **Wrong environment.** Testnet requests are signed with testnet keys. Set `environment: "testnet"` (or the testnet JWKS URL). Production uses the default.
  - production: `https://api.goassay.ai/.well-known/assay-request-keys.json`
  - testnet: `https://api-dev.goassay.ai/.well-known/assay-request-keys.json`
- **Your server cannot reach the key URL.** Check outbound HTTPS from your server, DNS and firewall rules. The verifier waits up to 5 seconds for the file. After a failed fetch it waits 5 seconds before it tries again, and during that time it answers `UNKNOWN_KEY` if it has no cached keys. After the pause it retries on its own and recovers once the network is back. You do not need to restart.
- **A key was rotated.** The verifier fetches the file again when it sees an unknown `keyid`, at most once per minute. Wait a minute and retry.

## WRONG_PROVIDER

The signature is valid, but Assay signed the request for a different provider than the one(s) your verifier is configured with (the `aud` parameter), or the request has no `aud` at all.

Likely causes and fixes:

- **Wrong provider id configured.** Set `provider` (Node, Python), `Providers` (Go) or `ASSAY_PROVIDER_ID` (Worker) to your Assay provider id exactly as shown in the portal. Several ids are allowed when one endpoint serves more than one of your providers.
- **Another provider pointed a binding at your API.** This is the case the check exists for. The request came from Assay, but on behalf of someone else, so refusing it is correct. See [overview.md](overview.md#why-the-audience-check-exists).
- **A signature without `aud`.** Assay adds `aud` to every request. A request without it is old or not from Assay's current signer, and is refused.

## Other reasons

| Reason | Meaning | Fix |
|---|---|---|
| `MISSING` | No `Signature` or `Signature-Input` header | The request did not come from Assay, or a proxy removed the headers. Let `Signature`, `Signature-Input` and `Content-Digest` through. |
| `MALFORMED` | A header or parameter is broken, or the request has a body that is not covered by `content-digest`, or the target starts with `//` | Check that a proxy does not edit the headers or the request line. |
| `WRONG_TAG` | The signature is valid for something else, not Assay requests | Not an Assay request. |

## Warnings in the Assay console tester

The binding tester in the Assay console sends test requests to your API and shows warnings. Here is what each means.

| Warning | What it means | What to do |
|---|---|---|
| **Signature not enforced** | Your API accepted a request with a missing or broken signature. Anyone can call it. | Add a verifier ([level 0](level-0-cloudflare-worker.md), [1](level-1-node.md) or [2](level-2-manual.md)). Then run the tester again. If you already added one, make sure it runs on this route and that the origin cannot be reached around it. |
| **API key not enforced** | Your API accepted a request without the API key you set up in Assay. | Make your API reject requests that do not carry the key header. Keys go in a header, never in the URL. |
| **No authentication** | Your API accepted a request with no signature and no API key at all. | Turn on at least one of them. Signature mode is the stronger one. See [overview.md](overview.md#choose-a-mode). |

After you fix a warning, run the tester again and confirm that it is gone.
