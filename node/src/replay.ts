export interface ReplayStore {
  /** Resolve true when the nonce was not seen before (and is now stored for ttlSeconds). */
  checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean>;
}

/** In-memory LRU replay store (insertion order; oldest entries evicted first). */
export class MemoryReplayStore implements ReplayStore {
  private readonly entries = new Map<string, number>(); // nonce -> expiry (ms)
  constructor(private readonly maxEntries = 100_000) {}

  async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
    const nowMs = Date.now();
    const existing = this.entries.get(nonce);
    if (existing !== undefined) {
      if (existing > nowMs) return false;
      this.entries.delete(nonce);
    }
    this.entries.set(nonce, nowMs + Math.max(0, ttlSeconds) * 1000);
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
    return true;
  }
}
