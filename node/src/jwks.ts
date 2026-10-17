export const JWKS_URL_PRODUCTION = "https://api.goassay.ai/.well-known/assay-request-keys.json";
export const JWKS_URL_TESTNET = "https://api-dev.goassay.ai/.well-known/assay-request-keys.json";

const CACHE_TTL_SECONDS = 3600;
const REFETCH_MIN_INTERVAL_SECONDS = 60;

export interface JwksSource {
  jwksUrl?: string;
  environment?: "production" | "testnet";
  jwks?: { keys: unknown[] };
  fetch?: typeof fetch;
}

const FETCH_TIMEOUT_MS = 5000;
const FAILURE_BACKOFF_SECONDS = 5;

interface Jwk { kty?: string; crv?: string; x?: string; kid?: string }

export function resolveJwksUrl(src: Pick<JwksSource, "jwksUrl" | "environment">): string {
  return src.jwksUrl ?? (src.environment === "testnet" ? JWKS_URL_TESTNET : JWKS_URL_PRODUCTION);
}

/** Caches imported Ed25519 public keys by kid. Clock (unix seconds) is passed per call. */
export class JwksCache {
  private keys = new Map<string, CryptoKey>();
  private loadedAt: number | undefined;
  private failedAt: number | undefined;
  private inflight: Promise<void> | undefined;
  private staticLoad: Promise<void> | undefined;
  readonly url: string;

  constructor(private readonly src: JwksSource) {
    this.url = resolveJwksUrl(src);
  }

  async getKey(kid: string, now: number): Promise<CryptoKey | undefined> {
    if (this.src.jwks) {
      this.staticLoad ??= this.load(this.src.jwks.keys);
      await this.staticLoad;
      return this.keys.get(kid);
    }
    // Never declare a kid unknown while a load is still in flight.
    if (this.inflight) await this.inflight;
    const fresh = this.loadedAt !== undefined && now - this.loadedAt < CACHE_TTL_SECONDS;
    if (fresh) {
      const hit = this.keys.get(kid);
      if (hit) return hit;
      // Unknown kid: refetch at most once per 60 s.
      if (now - this.loadedAt! < REFETCH_MIN_INTERVAL_SECONDS) return undefined;
    }
    // After a failed fetch, wait 5 s before trying again (cached keys stay usable).
    if (this.failedAt !== undefined && now - this.failedAt < FAILURE_BACKOFF_SECONDS) {
      return this.keys.get(kid);
    }
    this.inflight ??= this.fetchKeys(now).finally(() => { this.inflight = undefined; });
    await this.inflight;
    return this.keys.get(kid);
  }

  private async fetchKeys(now: number): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const doFetch = this.src.fetch ?? fetch;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("jwks fetch timeout")), FETCH_TIMEOUT_MS);
      });
      const work = (async () => {
        const res = await doFetch(this.url, {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        if (!res.ok) throw new Error("jwks http " + res.status);
        const body = (await res.json()) as { keys?: unknown };
        if (!body || !Array.isArray(body.keys)) throw new Error("jwks shape");
        await this.load(body.keys);
      })();
      work.catch(() => {});
      await Promise.race([work, timeout]);
      this.loadedAt = now; // only after the keys have been replaced
      this.failedAt = undefined;
    } catch {
      this.failedAt = now;
    } finally {
      if (timer) clearTimeout(timer);
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
