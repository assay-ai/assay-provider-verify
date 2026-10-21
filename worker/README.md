# Assay gateway Worker (level 0)

A Cloudflare Worker that checks the Assay signature on every request and forwards only valid ones to your API (`ORIGIN_URL`). See [docs/level-0-cloudflare-worker.md](../docs/level-0-cloudflare-worker.md).

## Develop

```
npm install
npm test            # runs vitest
npm run dry-run     # wrangler deploy --dry-run, no account needed
```

`package.json` pins the published `@goassay-ai/provider-verify` package, so a copy of this folder (the Deploy button copies only this folder) builds on its own. To test the Worker against unreleased changes in `../node`, run `npm install ../node` locally and do not commit the result.
