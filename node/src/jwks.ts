export const JWKS_URL_PRODUCTION = "https://api.goassay.ai/.well-known/assay-request-keys.json";
export const JWKS_URL_TESTNET = "https://api-dev.goassay.ai/.well-known/assay-request-keys.json";

const CACHE_TTL_SECONDS = 3600;
const REFETCH_MIN_INTERVAL_SECONDS = 60;

export interface JwksSource {
  jwksUrl?: string;
  environment?: "production" | "testnet";
  jwks?: { keys: unknown[] };
  fetch?: typeof fetch;
  /** Unix seconds. */
  now: () => number;
}

interface Jwk { kty?: string; crv?: string; x?: string; kid?: string }

/** Caches imported Ed25519 public keys by kid. */
export class JwksCache {
  private keys = new Map<string, CryptoKey>();
  private loadedAt: number | undefined;
  private inflight: Promise<boolean> | undefined;
  private readonly url: string;

  constructor(private readonly src: JwksSource) {
    this.url = src.jwksUrl ?? (src.environment === "testnet" ? JWKS_URL_TESTNET : JWKS_URL_PRODUCTION);
  }

  async getKey(kid: string): Promise<CryptoKey | undefined> {
    const now = this.src.now();
    if (this.src.jwks) {
      if (this.loadedAt === undefined) {
        this.loadedAt = now;
        await this.load(this.src.jwks.keys);
      }
      return this.keys.get(kid);
    }
    const fresh = this.loadedAt !== undefined && now - this.loadedAt < CACHE_TTL_SECONDS;
    if (fresh) {
      const hit = this.keys.get(kid);
      if (hit) return hit;
      // Unknown kid: refetch at most once per 60 s.
      if (now - this.loadedAt! < REFETCH_MIN_INTERVAL_SECONDS) return undefined;
    }
    await this.refresh();
    return this.keys.get(kid);
  }

  private refresh(): Promise<boolean> {
    // Concurrent callers share one fetch. A failed fetch is not rate limited,
    // so the next call retries; the previous keys stay usable until it succeeds.
    this.inflight ??= this.fetchKeys().finally(() => { this.inflight = undefined; });
    return this.inflight;
  }

  private async fetchKeys(): Promise<boolean> {
    try {
      const doFetch = this.src.fetch ?? fetch;
      const res = await doFetch(this.url, { headers: { accept: "application/json" } });
      if (!res.ok) return false;
      const body = (await res.json()) as { keys?: unknown };
      if (!body || !Array.isArray(body.keys)) return false;
      this.loadedAt = this.src.now();
      await this.load(body.keys);
      return true;
    } catch {
      return false;
    }
  }

  private async load(raw: unknown[]): Promise<void> {
    const next = new Map<string, CryptoKey>();
    for (const entry of raw) {
      const jwk = entry as Jwk;
      if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || typeof jwk.kid !== "string") continue;
      try {
        const key = await crypto.subtle.importKey(
          "jwk",
          { kty: "OKP", crv: "Ed25519", x: jwk.x },
          { name: "Ed25519" },
          false,
          ["verify"],
        );
        next.set(jwk.kid, key);
      } catch {
        // skip unusable key
      }
    }
    this.keys = next;
  }
}
