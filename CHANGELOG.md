# Changelog

All packages in this repository (npm `@goassay-ai/provider-verify`, PyPI `goassay-provider-verify`, the Go module and the Cloudflare Worker) share these notes.

## 0.2.0

### Breaking: the provider id is required

Every verifier now requires your Assay provider id and rejects requests that Assay signed for any other provider.

- Node: `provider` option (a string or an array) on `createVerifier`, `verifyAssayRequest` and every adapter (Express, Fastify, Hono, Next.js). Missing or invalid: a `TypeError` at setup.
- Python: `provider=` keyword on `Verifier`, `AssayVerifyMiddleware` and `AssayVerifyWSGI` (a string or a list). Missing: `TypeError`; empty or invalid: `ValueError`.
- Go: `Options.Providers`. Empty: `New` and `Middleware` return `ErrNoProvider`. `Verifier.Verify` now returns `(Result, error)`; `Result` has `KeyID`, `CallID`, `ProviderID` and `Reason`.
- Worker: the `ASSAY_PROVIDER_ID` variable (comma-separated for several). Missing or empty: every request gets `500` and nothing is forwarded to `ORIGIN_URL`.

There is no way to turn the check off.

### Why

Assay signs requests for every provider with the same keys, so a signature alone proved only "Assay sent this". Another provider could point one of its own bindings at your origin, and Assay would then send your API signed requests that a 0.1 verifier accepted (a confused deputy). Assay now adds the signature parameter `aud="<provider id>"`, always the provider that owns the calling binding. It is covered by the signature, and verifiers accept only the ids you configure.

### Other changes

- New reject reason `WRONG_PROVIDER` (HTTP `401`, like the other signature failures): `aud` is missing, not a string, or not one of your ids. It is checked only after the signature is verified, so unsigned requests learn nothing about which ids you accept, and before the nonce is stored.
- Successful results include the matched provider id: `providerId` (Node), `provider_id` (Python), `Result.ProviderID` (Go).
- Test vectors: `v1.json` cases carry `params.audience` and sign `aud`; `negative.json` has a top-level `provider` and new cases `wrong-provider`, `audience-missing`, `audience-not-string` and `audience-changed`.
- The covered components and the signature base format are unchanged.

### Upgrading

Set provider to your Assay provider id (shown in the portal):

```ts
app.use(assayVerify({ provider: "your-provider-id" }));                 // Node
```

```python
app.add_middleware(AssayVerifyMiddleware, provider="your-provider-id")  # Python
```

```go
assayverify.Middleware(assayverify.Options{Providers: []string{"your-provider-id"}}) // Go
```

Worker: set `ASSAY_PROVIDER_ID` in the Worker settings (or `wrangler.toml`) before deploying 0.2.0.

## 0.1.1 (Node only)

- Published with npm trusted publishing.

## 0.1.0

- First release: Node, Python and Go verifiers, the Cloudflare Worker gateway and the shared test vectors.
