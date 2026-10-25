# Assay gateway Worker (level 0)

A Cloudflare Worker that checks the Assay signature on every request and forwards only valid ones to your API (`ORIGIN_URL`).

Required variables:

- `ORIGIN_URL`: where valid requests are forwarded.
- `ASSAY_PROVIDER_ID`: your Assay provider id, shown in the portal (comma-separated for several). Requests signed for any other provider are refused with `WRONG_PROVIDER`. While it is missing or empty the Worker answers `500` and never calls the origin.

Upgrading from 0.1: set `ASSAY_PROVIDER_ID` before you deploy this version.

See [docs/level-0-cloudflare-worker.md](../docs/level-0-cloudflare-worker.md).

## Develop

```
npm install
npm test            # runs vitest
npm run dry-run     # wrangler deploy --dry-run, no account needed
```

`package.json` pins the published `@goassay-ai/provider-verify` package, so a copy of this folder (the Deploy button copies only this folder) builds on its own. To test the Worker against unreleased changes in `../node`, run `npm run build` in `../node`, then `npm install ../node` here, and do not commit the resulting `package.json` / `package-lock.json` changes.
