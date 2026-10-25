import { JwksCache, resolveJwksUrl } from "./jwks.js";
import { MemoryReplayStore, type ReplayStore } from "./replay.js";
import { parseDictionary, ParseError, type Member } from "./structured.js";

export type RejectReason =
  | "MISSING" | "MALFORMED" | "WRONG_TAG" | "EXPIRED"
  | "DIGEST_MISMATCH" | "UNKNOWN_KEY" | "BAD_SIGNATURE" | "WRONG_PROVIDER" | "REPLAYED";

export interface VerifyInput {
  method: string;
  url: string;
  headers: Headers | Record<string, string | string[] | undefined>;
  body: Uint8Array | null;
}

export type { ReplayStore };

export interface VerifyOptions {
  /**
   * REQUIRED. Your Assay provider id (shown in the portal), or a list of them.
   * Only requests signed for one of these providers (the `aud` signature
   * parameter) are accepted; anything else is rejected with WRONG_PROVIDER.
   */
  provider: string | readonly string[];
  jwksUrl?: string;
  environment?: "production" | "testnet";
  /** Overrides the @authority taken from the Host header. */
  authority?: string;
  replayStore?: ReplayStore;
  clockSkewSeconds?: number;
  /** Current time as unix SECONDS (default: Date.now() / 1000, floored). */
  now?: () => number;
  fetch?: typeof fetch;
  /** Static key set; disables fetching. */
  jwks?: { keys: unknown[] };
}

export type VerifyResult =
  | { ok: true; keyId: string; callId: string; providerId: string }
  | { ok: false; reason: RejectReason };

const BASE_COMPONENTS = ["@method", "@authority", "@path", "@query"];
const MAX_VALIDITY_SECONDS = 300;
const PROVIDER_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const enc = new TextEncoder();

function reject(reason: RejectReason): VerifyResult {
  return { ok: false, reason };
}

function getHeader(headers: VerifyInput["headers"], name: string): string | undefined {
  if (typeof (headers as Headers).get === "function" && !Array.isArray(headers)) {
    const v = (headers as Headers).get(name);
    return v === null ? undefined : v;
  }
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
    if (k.toLowerCase() !== lower || v === undefined) continue;
    return Array.isArray(v) ? v.join(", ") : v;
  }
  return undefined;
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function intParam(m: Member, name: string): number | undefined {
  const v = m.params.get(name);
  return typeof v === "number" && Number.isSafeInteger(v) ? v : undefined;
}

function strParam(m: Member, name: string): string | undefined {
  const v = m.params.get(name);
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

const ABSOLUTE = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Splits the request target. Absolute URLs use the URL parser (and supply a
 * fallback authority); anything else is taken as sent, never resolved.
 */
function parseTarget(url: string): { path: string; query: string; host?: string } | undefined {
  if (url.startsWith("//")) return undefined;
  if (ABSOLUTE.test(url)) {
    try {
      const u = new URL(url);
      if (u.pathname.startsWith("//")) return undefined;
      return { path: u.pathname || "/", query: u.search.replace(/^\?/, ""), host: u.host.toLowerCase() };
    } catch {
      return undefined;
    }
  }
  if (!url.startsWith("/")) return undefined;
  const noFrag = url.split("#", 1)[0]!;
  const q = noFrag.indexOf("?");
  return q < 0 ? { path: noFrag, query: "" } : { path: noFrag.slice(0, q), query: noFrag.slice(q + 1) };
}

/**
 * Authority rule: the `authority` option wins; else the Host header
 * (lowercased); else, when the request carries no Host header, the host of the
 * absolute request URL (lowercase, port only when not the scheme default).
 */
function resolveAuthority(input: VerifyInput, override: string | undefined, urlHost: string | undefined): string | undefined {
  if (override) return override.toLowerCase();
  const host = getHeader(input.headers, "host");
  if (host) return host.trim().toLowerCase();
  return urlHost;
}

async function verifyOnce(
  input: VerifyInput,
  options: VerifyOptions,
  providers: ReadonlySet<string>,
  jwks: JwksCache,
  replay: ReplayStore,
  now: () => number,
): Promise<VerifyResult> {
  // 1. Headers.
  const sigInputHeader = getHeader(input.headers, "signature-input");
  const sigHeader = getHeader(input.headers, "signature");
  if (!sigInputHeader || !sigHeader) return reject("MISSING");

  let inputMember: Member | undefined;
  let signature: Uint8Array;
  try {
    inputMember = parseDictionary(sigInputHeader).get("assay");
    const sigMember = parseDictionary(sigHeader).get("assay");
    if (!inputMember || !sigMember) return reject("MISSING");
    const item = sigMember.item;
    if (!item || typeof item !== "object") return reject("MALFORMED");
    signature = fromBase64(item.bytes);
  } catch (e) {
    if (e instanceof ParseError || e instanceof DOMException) return reject("MALFORMED");
    return reject("MALFORMED");
  }

  // 2. Parameters.
  const components = inputMember.list;
  if (!components) return reject("MALFORMED");
  const created = intParam(inputMember, "created");
  const expires = intParam(inputMember, "expires");
  const nonce = strParam(inputMember, "nonce");
  const keyid = strParam(inputMember, "keyid");
  const alg = inputMember.params.get("alg");
  const tag = inputMember.params.get("tag");
  if (tag !== "assay-request") return reject("WRONG_TAG");
  if (alg !== "ed25519" || created === undefined || expires === undefined || !nonce || !keyid) {
    return reject("MALFORMED");
  }

  // 3. Components and digest.
  const withDigest = components.includes("content-digest");
  const expected = withDigest
    ? [...BASE_COMPONENTS, "content-digest", "x-assay-call-id"]
    : [...BASE_COMPONENTS, "x-assay-call-id"];
  if (components.length !== expected.length || components.some((c, i) => c !== expected[i])) {
    return reject("MALFORMED");
  }
  const body = input.body ?? new Uint8Array(0);
  if (!withDigest && body.length > 0) return reject("MALFORMED");
  let digestValue: string | undefined;
  if (withDigest) {
    digestValue = getHeader(input.headers, "content-digest")?.trim();
    if (!digestValue) return reject("MISSING");
    let digestOk = false;
    try {
      const m = parseDictionary(digestValue).get("sha-256");
      const item = m?.item;
      if (item && typeof item === "object") {
        const actual = toBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", body as BufferSource)));
        digestOk = item.bytes === actual;
      }
    } catch {
      return reject("MALFORMED");
    }
    if (!digestOk) return reject("DIGEST_MISMATCH");
  }

  // 4. Time window.
  const skew = options.clockSkewSeconds ?? 60;
  const t = now();
  if (expires < created || expires - created > MAX_VALIDITY_SECONDS || t < created - skew || t > expires + skew) {
    return reject("EXPIRED");
  }

  // 5. Signature base.
  const callId = getHeader(input.headers, "x-assay-call-id")?.trim();
  if (!callId) return reject("MALFORMED");
  const target = parseTarget(input.url);
  if (!target) return reject("MALFORMED");
  const authority = resolveAuthority(input, options.authority, target.host);
  if (!authority) return reject("MALFORMED");
  const lines = [
    `"@method": ${input.method.toUpperCase()}`,
    `"@authority": ${authority}`,
    `"@path": ${target.path || "/"}`,
    `"@query": ?${target.query}`,
  ];
  if (digestValue !== undefined) lines.push(`"content-digest": ${digestValue}`);
  lines.push(`"x-assay-call-id": ${callId}`);
  lines.push(`"@signature-params": ${inputMember.raw}`);
  const base = enc.encode(lines.join("\n"));

  // 6. Key lookup and signature.
  const key = await jwks.getKey(keyid, t);
  if (!key) return reject("UNKNOWN_KEY");
  let valid = false;
  try {
    valid = await crypto.subtle.verify("Ed25519", key, signature as BufferSource, base);
  } catch {
    valid = false;
  }
  if (!valid) return reject("BAD_SIGNATURE");

  // 7. Audience: only after the signature holds, so unsigned probes learn nothing.
  const aud = inputMember.params.get("aud");
  if (typeof aud !== "string" || !providers.has(aud)) return reject("WRONG_PROVIDER");

  // 8. Replay.
  const ttl = Math.max(1, expires + skew - t);
  if (!(await replay.checkAndStore(nonce, ttl))) return reject("REPLAYED");

  return { ok: true, keyId: keyid, callId, providerId: aud };
}

type Verifier = (input: VerifyInput) => Promise<VerifyResult>;

/**
 * Validates the required `provider` option. Throws a TypeError when it is
 * missing, empty or not a valid provider id: there is no way to opt out.
 */
function providerSet(provider: unknown): ReadonlySet<string> {
  const list = typeof provider === "string" ? [provider] : Array.isArray(provider) ? provider : undefined;
  if (!list || list.length === 0) {
    throw new TypeError("assay-provider-verify: the `provider` option is required (your Assay provider id, shown in the portal)");
  }
  for (const id of list) {
    if (typeof id !== "string" || !PROVIDER_ID.test(id)) {
      throw new TypeError(`assay-provider-verify: invalid provider id ${JSON.stringify(id)}`);
    }
  }
  return new Set(list as string[]);
}

function build(options: VerifyOptions, cache: () => JwksCache, replay: ReplayStore): Verifier {
  const providers = providerSet((options as Partial<VerifyOptions> | undefined)?.provider);
  const jwks = cache();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  return (input) => verifyOnce(input, options, providers, jwks, replay, now);
}

function newCache(options: VerifyOptions): JwksCache {
  return new JwksCache({ jwksUrl: options.jwksUrl, environment: options.environment, jwks: options.jwks, fetch: options.fetch });
}

/**
 * Builds a reusable verifier. Throws when `provider` is missing or invalid.
 * The JWKS cache is shared process-wide per resolved
 * URL (like `verifyAssayRequest`). The replay store is the one given, otherwise a
 * new in-memory store owned by this verifier.
 */
export function createVerifier(options: VerifyOptions): Verifier {
  return build(options, () => sharedCache(options), options?.replayStore ?? new MemoryReplayStore());
}

// One-shot helper state: a process-wide default replay store, and JWKS caches
// shared per resolved URL (per fetch function when a custom one is given; per
// key-set object for static keys).
const sharedReplay = new MemoryReplayStore();
const urlCaches = new Map<string, JwksCache>();
const customFetchCaches = new WeakMap<object, Map<string, JwksCache>>();
const staticCaches = new WeakMap<object, JwksCache>();

function sharedCache(options: VerifyOptions): JwksCache {
  if (options.jwks) {
    let c = staticCaches.get(options.jwks);
    if (!c) staticCaches.set(options.jwks, (c = newCache(options)));
    return c;
  }
  const url = resolveJwksUrl(options);
  let map = urlCaches;
  if (options.fetch) {
    let m = customFetchCaches.get(options.fetch);
    if (!m) customFetchCaches.set(options.fetch, (m = new Map()));
    map = m;
  }
  let c = map.get(url);
  if (!c) map.set(url, (c = newCache(options)));
  return c;
}

/**
 * One-shot helper. Throws (synchronously) when `provider` is missing or
 * invalid. Replay protection (unless a replayStore is passed) and JWKS
 * caches are shared process-wide, so fresh options objects per call are fine.
 */
export function verifyAssayRequest(input: VerifyInput, options: VerifyOptions): Promise<VerifyResult> {
  return build(options, () => sharedCache(options), options?.replayStore ?? sharedReplay)(input);
}

export { MemoryReplayStore };
