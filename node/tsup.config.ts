import { defineConfig } from "tsup";

// Core plus the express, fastify, hono, next and redis adapters (all six entries).
import { existsSync } from "node:fs";

const candidates: Record<string, string> = {
  index: "src/index.ts",
  express: "src/express.ts",
  fastify: "src/fastify.ts",
  hono: "src/hono.ts",
  next: "src/next.ts",
  redis: "src/redis.ts",
};
const entry = Object.fromEntries(Object.entries(candidates).filter(([, p]) => existsSync(p)));

export default defineConfig({
  entry,
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  target: "es2022",
  platform: "neutral",
});
