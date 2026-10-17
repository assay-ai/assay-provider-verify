# assay-provider-verify

Verify that an API request really comes from [Assay](https://goassay.ai).

Assay signs every request it forwards to your API with an Ed25519 signature (HTTP Message Signatures, RFC 9421 style). This repository has ready-made verifiers so you can reject anything that is not from Assay. Pick the level that fits your setup.

| Level | You run | Use it when | Where |
|---|---|---|---|
| Middleware | Node, Python or Go server | You can add a few lines to your app | `node/`, `python/`, `go/` |
| Library | Anything else | You want only the verify function and handle the response yourself | `node/`, `python/`, `go/` |
| Gateway worker | Cloudflare in front of your API | You do not want to change your app | `worker/` |
| Reference | Another language | You will write your own verifier | [docs/overview.md](docs/overview.md) and `test-vectors/` |

## Quick start

Packages: npm `@assay-ai/provider-verify`, PyPI `assay-provider-verify`, Go `github.com/assay-ai/assay-provider-verify/go`. Each language folder has its own README with the exact three lines for your framework.

Keys are fetched automatically from:

- production: `https://api.goassay.ai/.well-known/assay-request-keys.json` (default)
- testnet: `https://api-dev.goassay.ai/.well-known/assay-request-keys.json` (set `environment: "testnet"`)

A rejected request gets `401` with body `{"error":"invalid_assay_signature","reason":"<CODE>"}`.

## Documentation

- [docs/overview.md](docs/overview.md): how the signature works, the verification steps, reason codes and the test vectors.

## Test vectors

`test-vectors/v1.json` has valid signed requests, `test-vectors/negative.json` has requests that must be rejected for a specific reason. Every implementation in this repository runs them. The seed inside is public and for tests only.

## License

MIT, see [LICENSE](LICENSE).
