import type { ReplayStore } from "./replay.js";

interface AnyClient {
  set(...args: unknown[]): Promise<unknown>;
  [key: string]: unknown;
}

/**
 * Replay store backed by Redis (SET NX EX). Works with node-redis v4+
 * (`set(key, val, { NX: true, EX })`) and ioredis (`set(key, val, "EX", s, "NX")`)
 * without importing either library. Redis errors propagate (verification fails closed).
 */
export function redisReplayStore(client: unknown, prefix = "assay:nonce:"): ReplayStore {
  const c = client as AnyClient;
  if (!c || typeof c.set !== "function") throw new TypeError("redisReplayStore: client must expose set()");
  // ioredis exposes `status` and `pipeline`; node-redis exposes `isOpen`/`isReady`.
  const isIoredis = !("isOpen" in c) && !("isReady" in c) && (typeof c.status === "string" || typeof c.pipeline === "function");
  return {
    async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
      const key = prefix + nonce;
      const ex = Math.max(1, Math.ceil(ttlSeconds));
      const res = isIoredis ? await c.set(key, "1", "EX", ex, "NX") : await c.set(key, "1", { NX: true, EX: ex });
      return res === "OK";
    },
  };
}
