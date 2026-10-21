# Assay gateway Worker (level 0)

A Cloudflare Worker that checks the Assay signature on every request and forwards only valid ones to your API (`ORIGIN_URL`). See [docs/level-0-cloudflare-worker.md](../docs/level-0-cloudflare-worker.md).

## Develop

```
npm install
npm test            # builds ../node first (pretest), then runs vitest
npm run dry-run     # wrangler deploy --dry-run, no account needed
```

`package.json` depends on `"@goassay-ai/provider-verify": "file:../node"` so that this repository tests the Worker against the code next to it. The Deploy button copies only this folder, so before you publish a template or deploy from a copy, change that line to the published version, for example `"@goassay-ai/provider-verify": "^0.1.0"`, and delete the `pretest` and `predry-run` scripts.
