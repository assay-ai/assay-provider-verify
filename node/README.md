# @assay-ai/provider-verify

Verify that a request to your API really comes from [Assay](https://goassay.ai). Assay signs every
request it forwards with an Ed25519 signature (HTTP Message Signatures, RFC 9421 style); this package
checks it with WebCrypto only. Zero runtime dependencies, Node 20 or newer. Framework packages are
optional peer dependencies.

```sh
npm install @assay-ai/provider-verify
```

Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your handler
unchanged; the raw body stays available.

## One line per framework

```ts
// Express: mount before any body parser; sets req.rawBody
import { assayVerify } from "@assay-ai/provider-verify/express";
app.use(assayVerify());

// Fastify
import { assayVerifyPlugin } from "@assay-ai/provider-verify/fastify";
await app.register(assayVerifyPlugin);

// Hono
import { assayVerify } from "@assay-ai/provider-verify/hono";
app.use("*", assayVerify());

// Next.js route handlers (the route context, e.g. { params }, is passed through)
import { withAssayVerify } from "@assay-ai/provider-verify/next";
export const POST = withAssayVerify(async (req, ctx) => Response.json(await req.json()));
```

Without a framework, call the function yourself:

```ts
import { verifyAssayRequest } from "@assay-ai/provider-verify";

const result = await verifyAssayRequest({ method, url, headers, body }); // body: raw bytes, or null
if (!result.ok) console.log(result.reason);
```

Testnet keys: pass `{ environment: "testnet" }`. Behind a proxy that rewrites `Host`, pass
`{ authority: "api.example.com" }`. With more than one instance, use the Redis replay store from
`@assay-ai/provider-verify/redis`.

## Documentation

- [Node guide](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/level-1-node.md): every adapter, options, Redis, proxies, local testing.
- [Troubleshooting](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/troubleshooting.md): what each reject reason means.
- [How the signature works](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/overview.md).

## License

MIT, see [LICENSE](LICENSE).
