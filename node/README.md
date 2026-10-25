# @goassay-ai/provider-verify

Verify that a request to your API really comes from [Assay](https://goassay.ai). Assay signs every
request it forwards with an Ed25519 signature (HTTP Message Signatures, RFC 9421 style); this package
checks it with WebCrypto only. Zero runtime dependencies, Node 20 or newer. Framework packages are
optional peer dependencies.

```sh
npm install @goassay-ai/provider-verify
```

Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your handler
unchanged; the raw body stays available.

## One line per framework

```ts
const PROVIDER = "your-provider-id"; // your Assay provider id, shown in the portal (required)

// Express: mount before any body parser; sets req.rawBody
import { assayVerify } from "@goassay-ai/provider-verify/express";
app.use(assayVerify({ provider: PROVIDER }));

// Fastify
import { assayVerifyPlugin } from "@goassay-ai/provider-verify/fastify";
await app.register(assayVerifyPlugin, { provider: PROVIDER });

// Hono
import { assayVerify } from "@goassay-ai/provider-verify/hono";
app.use("*", assayVerify({ provider: PROVIDER }));

// Next.js route handlers (the route context, e.g. { params }, is passed through)
import { withAssayVerify } from "@goassay-ai/provider-verify/next";
export const POST = withAssayVerify(async (req, ctx) => Response.json(await req.json()), { provider: PROVIDER });
```

Without a framework, call the function yourself:

```ts
import { verifyAssayRequest } from "@goassay-ai/provider-verify";

const result = await verifyAssayRequest({ method, url, headers, body }, { provider: PROVIDER }); // body: raw bytes, or null
if (!result.ok) console.log(result.reason);
else console.log(result.providerId); // the matched provider id
```

`provider` is required (an array of ids is allowed); without it the adapter or function throws. Assay
signs requests for every provider with the same keys, so a request it signed for another provider is
rejected with `WRONG_PROVIDER`. Testnet keys: pass `{ environment: "testnet" }`. Behind a proxy that rewrites `Host`, pass
`{ authority: "api.example.com" }`. With more than one instance, use the Redis replay store from
`@goassay-ai/provider-verify/redis`.

## Upgrading from 0.1

0.2.0 makes `provider` required and adds the reject reason `WRONG_PROVIDER`. Set provider to your
Assay provider id (shown in the portal). See the
[changelog](https://github.com/assay-ai/assay-provider-verify/blob/main/CHANGELOG.md).

## Documentation

- [Node guide](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/level-1-node.md): every adapter, options, Redis, proxies, local testing.
- [Troubleshooting](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/troubleshooting.md): what each reject reason means.
- [How the signature works](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/overview.md).

## License

MIT, see [LICENSE](LICENSE).
