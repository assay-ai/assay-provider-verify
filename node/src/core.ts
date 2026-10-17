import { JwksCache } from "./jwks.js";
import { MemoryReplayStore, type ReplayStore } from "./replay.js";
import { parseDictionary, ParseError, type Member } from "./structured.js";

export type RejectReason =
  | "MISSING" | "MALFORMED" | "WRONG_TAG" | "EXPIRED"
  | "DIGEST_MISMATCH" | "UNKNOWN_KEY" | "BAD_SIGNATURE" | "REPLAYED";

export interface VerifyInput {
  method: string;
  url: string;
  headers: Headers | Record<string, string | string[] | undefined>;
  body: Uint8Array | null;
}

export type { ReplayStore };

export interface VerifyOptions {
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
  | { ok: true; keyId: string; callId: string }
  | { ok: false; reason: RejectReason };

const BASE_COMPONENTS = ["@method", "@authority", "@path", "@query"];
const MAX_VALIDITY_SECONDS = 300;
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

/**
 * Authority rule: the `authority` option wins; else the Host header
 * (lowercased); else, when the request carries no Host header, the host of the
 * request URL (lowercase, port only when not the scheme default).
 */
function resolveAuthority(input: VerifyInput, override: string | undefined, parsed: URL): string {
  if (override) return override.toLowerCase();
  const host = getHeader(input.headers, "host");
  if (host) return host.trim().toLowerCase();
  return parsed.host.toLowerCase();
}

async function verifyOnce(
  input: VerifyInput,
  options: VerifyOptions,
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
  if (expires - created > MAX_VALIDITY_SECONDS || t < created - skew || t > expires + skew) {
    return reject("EXPIRED");
  }

  // 5. Signature base.
  const callId = getHeader(input.headers, "x-assay-call-id")?.trim();
  if (!callId) return reject("MALFORMED");
  let parsed: URL;
  try {
    parsed = new URL(input.url, "http://placeholder.invalid");
  } catch {
    return reject("MALFORMED");
  }
  const lines = [
    `"@method": ${input.method.toUpperCase()}`,
    `"@authority": ${resolveAuthority(input, options.authority, parsed)}`,
    `"@path": ${parsed.pathname || "/"}`,
    `"@query": ?${parsed.search.replace(/^\?/, "")}`,
  ];
  if (digestValue !== undefined) lines.push(`"content-digest": ${digestValue}`);
  lines.push(`"x-assay-call-id": ${callId}`);
  lines.push(`"@signature-params": ${inputMember.raw}`);
  const base = enc.encode(lines.join("\n"));

  // 6. Key lookup and signature.
  const key = await jwks.getKey(keyid);
  if (!key) return reject("UNKNOWN_KEY");
  let valid = false;
  try {
    valid = await crypto.subtle.verify("Ed25519", key, signature as BufferSource, base);
  } catch {
    valid = false;
  }
  if (!valid) return reject("BAD_SIGNATURE");

  // 7. Replay.
  const ttl = Math.max(1, expires + skew - t);
  if (!(await replay.checkAndStore(nonce, ttl))) return reject("REPLAYED");

  return { ok: true, keyId: keyid, callId };
}

/** Builds a verifier that shares one JWKS cache and one replay store across calls. */
export function createVerifier(options: VerifyOptions = {}): (input: VerifyInput) => Promise<VerifyResult> {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const replay = options.replayStore ?? new MemoryReplayStore();
  const jwks = new JwksCache({
    jwksUrl: options.jwksUrl,
    environment: options.environment,
    jwks: options.jwks,
    fetch: options.fetch,
    now,
  });
  return (input) => verifyOnce(input, options, jwks, replay, now);
}

const verifiers = new WeakMap<object, (input: VerifyInput) => Promise<VerifyResult>>();
let defaultVerifier: ((input: VerifyInput) => Promise<VerifyResult>) | undefined;

/**
 * One-shot helper. Verifiers are memoised per options object (and one default
 * for no options), so JWKS cache and replay store persist across calls as long
 * as the same options object is passed.
 */
export function verifyAssayRequest(input: VerifyInput, options?: VerifyOptions): Promise<VerifyResult> {
  if (!options) return (defaultVerifier ??= createVerifier())(input);
  let v = verifiers.get(options);
  if (!v) verifiers.set(options, (v = createVerifier(options)));
  return v(input);
}

export { MemoryReplayStore };
