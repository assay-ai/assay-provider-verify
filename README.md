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

Packages: npm `@assay-ai/provider-verify`, PyPI `assay-provider-verify`, Go `github.com/assay-ai/assay-provider-verify/go`. Each package folder (`node/`, `python/`, `go/`, `worker/`) has its own README with the lines to add for your framework.

Keys are fetched automatically from:

- production: `https://api.goassay.ai/.well-known/assay-request-keys.json` (default)
- testnet: `https://api-dev.goassay.ai/.well-known/assay-request-keys.json` (set `environment: "testnet"`)

A rejected request gets `401` with body `{"error":"invalid_assay_signature","reason":"<CODE>"}`.

## Deploy without code

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/assay-ai/assay-provider-verify/tree/main/worker)

The button works once this repository is public. Steps: [docs/level-0-cloudflare-worker.md](docs/level-0-cloudflare-worker.md).

## Documentation

- [docs/level-0-cloudflare-worker.md](docs/level-0-cloudflare-worker.md): the zero-code Cloudflare Worker.
- [docs/level-1-node.md](docs/level-1-node.md), [docs/level-1-python.md](docs/level-1-python.md) and [docs/level-1-go.md](docs/level-1-go.md): middleware for Node, Python and Go.
- [docs/level-2-manual.md](docs/level-2-manual.md): write the check yourself, with a worked example.
- [docs/troubleshooting.md](docs/troubleshooting.md): what each reject reason and console warning means.
- [docs/overview.md](docs/overview.md): API-key and signature modes, how the signature works, the verification steps, reason codes and the test vectors.

## Test vectors

`test-vectors/v1.json` has valid signed requests, `test-vectors/negative.json` has requests that must be rejected for a specific reason. Every implementation in this repository runs them. The seed inside is public and for tests only.

## Release checklist

For maintainers.

- Tag `node/vX.Y.Z`, `python/vX.Y.Z` or `go/vX.Y.Z` to publish that package (`.github/workflows/release.yml`). Go needs only the tag.
- Tokens are repository secrets set by the owner: `NPM_TOKEN` for npm. PyPI uses trusted publishing (preferred) or a `PYPI_TOKEN` secret.
- Before announcing the Deploy button, switch `worker/package.json` from `"@assay-ai/provider-verify": "file:../node"` to the published version, and check the Worker still builds.
- Check the Deploy button's subdirectory URL and the free-plan limits quoted in [docs/level-0-cloudflare-worker.md](docs/level-0-cloudflare-worker.md) against Cloudflare's current documentation.

## License

MIT, see [LICENSE](LICENSE).
