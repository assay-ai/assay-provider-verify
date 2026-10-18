# Level 0: Cloudflare Worker (no code)

Put a Worker in front of your API. It checks the Assay signature and passes only valid requests to your server. Your app does not change.

```
Assay -> Worker (checks signature) -> your origin
```

## Steps

1. **Deploy.** Press the "Deploy to Cloudflare" button in the [README](../README.md). Cloudflare copies the `worker/` folder into your account.
2. **Set `ORIGIN_URL`.** In the Worker settings, set the variable `ORIGIN_URL` to your real API, for example `https://origin.example.com`. A path prefix is allowed. The Worker forwards the original path and query after it.
3. **Add a route or custom domain.** Attach the Worker to the hostname Assay calls (for example `api.yourcompany.com`). The signature covers that hostname, so Assay must call the Worker's hostname, not the origin's.
4. **Make your origin reachable only from the Worker.** Otherwise anyone can skip the check by calling the origin directly. Two simple ways:
   - **Secret header.** Run `npx wrangler secret put ORIGIN_SECRET`. The Worker then adds `x-assay-origin-secret: <value>` to every forwarded request. Make your origin (or its firewall) reject requests without it.
   - **Cloudflare Tunnel.** Expose the origin only through a tunnel and do not open its public port.
5. **Test it.** Run the binding tester in the Assay console. You should see no "Signature not enforced" warning.

## What the Worker does

- Valid request: forwarded with the same method and body to `ORIGIN_URL` + path + query. The headers `signature`, `signature-input` and `content-digest` are removed (and `host`). `x-assay-call-id` is kept.
- Invalid request: `401` with `{"error":"invalid_assay_signature","reason":"<CODE>"}`. The origin is never called.
- Body larger than 5 MiB: `413` before any check.
- Redirects from your origin are returned to the caller as they are. The Worker never follows them.
- Testnet keys: set `JWKS_URL` to `https://api-dev.goassay.ai/.well-known/assay-request-keys.json`.

## Limits on the free plan

The Workers free plan allows 100,000 requests per day and a small CPU budget (10 ms per request). Signature checking is light, but a very busy API may need the paid plan. Check Cloudflare's current limits page. Bodies are held in memory (up to 5 MiB), so large uploads are not a fit for this level.

## Replay protection and the Durable Object

Every signature has a one-time nonce. The Worker must remember nonces to refuse a replayed request.

- **Default (no setup).** Each Worker instance remembers nonces in its own memory. This is **not** cross-instance replay protection: Cloudflare runs many instances and they restart often, so an attacker who captured a request could replay it against another instance within the 5 minute validity window. Signatures still expire, and a replay cannot change the request.
- **With the `NonceStore` Durable Object.** One object remembers every nonce, so a replay is refused everywhere. To turn it on, uncomment the two blocks at the end of `worker/wrangler.toml` (`[[durable_objects.bindings]]` for `NONCE_STORE`, and the `[[migrations]]` block that creates the SQLite-backed `NonceStore` class), then deploy. Trade-offs: every request makes one extra call to the object, which adds latency, and the object lives in one region. Set `NONCE_LOCATION_HINT` (for example `weur`, `enam`, `apac`) near your origin to keep that call short. It is also one more billed component.
- **If the Durable Object fails.** When `NONCE_STORE` is set and the object errors or cannot be reached, the Worker fails closed: it answers `503` with `{"error":"replay_store_unavailable"}` and does not call your origin. The object stores nonces in its SQLite storage and deletes expired ones with an alarm.
