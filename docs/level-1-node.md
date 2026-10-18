# Level 1 - Node.js

Verify Assay request signatures in one line. The package has zero runtime dependencies; framework
packages are optional peer dependencies.

```sh
npm install @assay-ai/provider-verify
```

Node 20 or newer. Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your handler
unchanged; the raw body stays available.

## Express

Mount it before any body parser (it needs the raw bytes). After a successful verification it sets
`req.rawBody` (a `Buffer`), fills `req.body` when unset (parsed JSON for JSON content types, otherwise
the raw `Buffer`) and marks the body as parsed, so a later `express.json()` is a harmless no-op.

```ts
import { assayVerify } from "@assay-ai/provider-verify/express";

app.use(assayVerify());
app.use(express.json()); // optional: no-op, the body is already parsed
```

If a body parser ran first, the middleware answers `500` ("mount assayVerify() before body parsers")
instead of guessing.

## Fastify

```ts
import { assayVerifyPlugin } from "@assay-ai/provider-verify/fastify";

await app.register(assayVerifyPlugin);
```

The plugin is not encapsulated, so it covers all routes. It captures the raw body in a `preParsing`
hook and sets `request.rawBody`.

## Hono

```ts
import { assayVerify } from "@assay-ai/provider-verify/hono";

app.use("*", assayVerify());
```

## Next.js route handlers

```ts
import { withAssayVerify } from "@assay-ai/provider-verify/next";

export const POST = withAssayVerify(async (req) => Response.json(await req.json()));

// Dynamic routes: the route context (for example { params }) is passed through unchanged.
export const GET = withAssayVerify(async (req, { params }: { params: Promise<{ id: string }> }) =>
  Response.json({ id: (await params).id }),
);
```

## Options

`assayVerify(options)` / `withAssayVerify(handler, options)` take the same `VerifyOptions` as
`verifyAssayRequest`: `environment: "testnet"` (or `jwksUrl`), `authority`, `replayStore`,
`clockSkewSeconds`, and `maxBodyBytes` (default 5 MiB; the body is buffered before authentication, larger
bodies get `413 {"error":"payload_too_large"}` without verifying). Each adapter creates one verifier at setup, so the JWKS cache (1 hour) and the replay
store are shared by all requests.

## Multiple instances and Redis

The default replay store is in memory (LRU, 100 000 entries) and per process. With more than one
instance, use a shared store so a nonce replayed against another instance is still caught:

```ts
import { createClient } from "redis"; // node-redis v4+, or ioredis
import { redisReplayStore } from "@assay-ai/provider-verify/redis";

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

app.use(assayVerify({ replayStore: redisReplayStore(redis) })); // key prefix "assay:nonce:"
```

`redisReplayStore(client, prefix?)` uses `SET key 1 NX EX <ttl>` and works with node-redis v4+ and
ioredis without importing either. Redis errors are not swallowed: verification fails closed.

## Proxies and the `authority` option

The signature covers `@authority`, the host the caller used. By default it is read from the `Host`
header. If a proxy or load balancer rewrites `Host` (or your framework sees an internal host), set the
public host explicitly:

```ts
app.use(assayVerify({ authority: "api.example.com" })); // include :port if not the scheme default
```

## Testing locally with the vectors

`test-vectors/v1.json` holds signed requests and a TEST ONLY public key. Inject it and pin the clock to
the vector's `created` time so nothing is fetched and nothing expires:

```ts
const v1 = JSON.parse(fs.readFileSync("test-vectors/v1.json", "utf8"));
const c = v1.cases[0];
app.use(assayVerify({
  jwks: { keys: [v1.publicKeyJwk] },
  now: () => c.params.created,
  authority: new URL(c.request.url).host.toLowerCase(),
}));
// Send c.request.method / path / body with the headers from c.request.headers and c.expected.headers.
```

Changing one byte of the body returns `DIGEST_MISMATCH`. Replaying the same request returns `REPLAYED`.
See `node/test/adapters.test.ts` for working examples.
