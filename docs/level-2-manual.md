# Level 2 - Verify by hand

Use this page if there is no ready-made package for your language, or if you want to see exactly what a verifier does. A hand-written verifier is about 40 lines. The full contract is in [overview.md](overview.md). This page walks through it with a real example.

If you use Node, Python or Go, level 1 is easier. If you do not want to change your app at all, use [level 0](level-0-cloudflare-worker.md).

## What you need

- The public keys (a JWKS file). Production: `https://api.goassay.ai/.well-known/assay-request-keys.json`. Testnet: `https://api-dev.goassay.ai/.well-known/assay-request-keys.json`.
- The raw request body bytes, before any JSON parsing.
- The request target exactly as the client sent it, for example `/v1/search?q=a%20b`.
- The `Host` header.
- Your Assay provider id, shown in the portal (or several, if you run more than one provider on this endpoint).

## The steps in plain words

1. Read the `Signature-Input` and `Signature` headers. Use the member called `assay`. If either header is missing, reject with `MISSING`. If you cannot parse them, reject with `MALFORMED`.
2. Read the parameters. `tag` must be `"assay-request"` (else `WRONG_TAG`). `alg` must be `"ed25519"`. `created` and `expires` must be integers. `nonce` and `keyid` must not be empty. Anything else is `MALFORMED`.
3. Check the list of signed parts. It must be exactly `"@method" "@authority" "@path" "@query" "x-assay-call-id"`. When `"content-digest"` is signed, it sits just before `"x-assay-call-id"`. If the request has a body but `content-digest` is not signed, reject with `MALFORMED`. If it is signed, hash the raw body with SHA-256 and compare it to the `Content-Digest` header. A difference is `DIGEST_MISMATCH`.
4. Check the time. You need `created - 60 <= now <= expires + 60`, and `expires - created <= 300`. If `expires` is smaller than `created`, or the time does not fit, reject with `EXPIRED`.
5. Rebuild the signature base (next section) from the request you received.
6. Find the key whose `kid` equals `keyid` in the JWKS. No match: `UNKNOWN_KEY`. Check the Ed25519 signature over the signature base. Bad signature: `BAD_SIGNATURE`.
7. Check the audience. The `aud` parameter must be a string equal to your own provider id (or one of yours). Missing, not a string, or another provider's id: `WRONG_PROVIDER`. Assay signs every outbound request with the same keys, so without this check a request Assay made for another provider, pointed at your endpoint, would verify. Do this only after the signature is good, so that an unsigned request learns nothing about which ids you accept.
8. Check the nonce. If you saw it before, reject with `REPLAYED`. Otherwise remember it until `expires + 60` seconds. Only do this after the signature is good, so that an attacker cannot fill your store with fake nonces.

Reject with status `401`, header `content-type: application/json` and body `{"error":"invalid_assay_signature","reason":"<CODE>"}`.

## Rules that are easy to get wrong

- **Use the path and query exactly as sent.** Take them from the request target (the part after the method on the first line). Do not decode, resolve, normalise or re-encode them. `a%20b` stays `a%20b`. `/a/../b` stays `/a/../b`.
- **Reject targets that start with `//`.** A target like `//evil.test/x` can be read as a host by some servers. Reject it with `MALFORMED`. A target must start with a single `/`.
- **Use the raw body.** Hash the bytes you received. Never hash a parsed and re-serialised JSON value.
- **`@authority` is the `Host` header as received, in lowercase.** Do not add or remove a port. Assay signs the host it calls, with `:port` only when the port is not the scheme default, and sends that same value as `Host`, so the header matches when nothing in between changes it. If a proxy rewrites `Host` or the port (for example to an internal name or `:8080`), use the public host you configured instead of the header, as the SDKs do with their `authority` option.
- **Do not follow redirects.** See [troubleshooting](troubleshooting.md#my-endpoint-redirects).
- **Never skip the audience check.** A valid signature only proves that Assay sent the request, not that it was meant for you. Configure your provider id and refuse every other `aud`.
- **Never skip the check on error.** If anything fails (network, parsing, a crash), reject the request.

## The signature base

The signature base is the text that was signed. Build it with one line per signed part, in order:

```
"<name>": <value>
```

The last line is `"@signature-params": ` followed by the inner list and the parameters, copied from the `Signature-Input` header (everything after `assay=`). Join the lines with a single `\n`. There is no newline at the end.

Values:

| Part | Value |
|---|---|
| `@method` | The method in uppercase, for example `POST` |
| `@authority` | The `Host` header as received, in lowercase (or your configured public host) |
| `@path` | The path as sent. `/` if it is empty |
| `@query` | `?` followed by the query as sent. Just `?` if there is no query |
| `content-digest` | The `Content-Digest` value: `sha-256=:<base64 of SHA-256 of the raw body>:` |
| `x-assay-call-id` | The value of the `X-Assay-Call-Id` header |

## Worked example

This is the first case in `test-vectors/v1.json`. You can follow it with any tool.

The request as it arrives:

```
POST /v1/search?q=a%20b HTTP/1.1
Host: API.Example.test
X-Assay-Call-Id: c-1
Content-Digest: sha-256=:dm7Bv3nwO4zfpapceY8ZEGZiaYiTOc8C3j72DLhHCSw=:
Signature-Input: assay=("@method" "@authority" "@path" "@query" "content-digest" "x-assay-call-id");created=1760700000;expires=1760700300;nonce="AQEBAQEBAQEBAQEBAQEBAQ";keyid="test-2026-10";alg="ed25519";tag="assay-request";aud="prov-test-1"
Signature: assay=:IFxcqvc1PcRd67uZmHG1tjUcnDTM2wxLYl5JIOss4lUJdbCwNailgWR3RVZkDLsPg2mlNbnH3cTWhmhEvhrwAQ==:

{"q":"a b"}
```

The body is the 11 bytes `{"q":"a b"}`.

**Step 2. Parameters.** `created=1760700000`, `expires=1760700300`, `nonce="AQEBAQEBAQEBAQEBAQEBAQ"`, `keyid="test-2026-10"`, `alg="ed25519"`, `tag="assay-request"`, `aud="prov-test-1"`. All present and valid. (`aud` is checked in step 7.)

**Step 3. Signed parts and digest.** The list is `"@method" "@authority" "@path" "@query" "content-digest" "x-assay-call-id"`. That is the expected list for a request with a body. The SHA-256 of the 11 body bytes, in base64, is `dm7Bv3nwO4zfpapceY8ZEGZiaYiTOc8C3j72DLhHCSw=`. So the digest string is:

```
sha-256=:dm7Bv3nwO4zfpapceY8ZEGZiaYiTOc8C3j72DLhHCSw=:
```

It equals the `Content-Digest` header.

**Step 4. Time.** `expires - created = 300`. At `now = 1760700000` the check passes.

**Step 5. Values for the base.**

| Part | Value |
|---|---|
| `@method` | `POST` |
| `@authority` | `api.example.test` (the `Host` header lowercased) |
| `@path` | `/v1/search` |
| `@query` | `?q=a%20b` |
| `content-digest` | `sha-256=:dm7Bv3nwO4zfpapceY8ZEGZiaYiTOc8C3j72DLhHCSw=:` |
| `x-assay-call-id` | `c-1` |

The parameter string (from `Signature-Input`, after `assay=`) is:

```
("@method" "@authority" "@path" "@query" "content-digest" "x-assay-call-id");created=1760700000;expires=1760700300;nonce="AQEBAQEBAQEBAQEBAQEBAQ";keyid="test-2026-10";alg="ed25519";tag="assay-request";aud="prov-test-1"
```

The signature base, exactly as signed (7 lines, no newline at the end):

```
"@method": POST
"@authority": api.example.test
"@path": /v1/search
"@query": ?q=a%20b
"content-digest": sha-256=:dm7Bv3nwO4zfpapceY8ZEGZiaYiTOc8C3j72DLhHCSw=:
"x-assay-call-id": c-1
"@signature-params": ("@method" "@authority" "@path" "@query" "content-digest" "x-assay-call-id");created=1760700000;expires=1760700300;nonce="AQEBAQEBAQEBAQEBAQEBAQ";keyid="test-2026-10";alg="ed25519";tag="assay-request";aud="prov-test-1"
```

**Step 6. Key and signature.** `keyid` is `test-2026-10`. The matching key in the JWKS is the public key from the test vectors:

```json
{ "kty": "OKP", "crv": "Ed25519", "x": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg", "kid": "test-2026-10", "use": "sig", "alg": "EdDSA" }
```

The signature is the base64 text between the colons in the `Signature` header (`IFxcqvc1...rwAQ==`). Decoded, it is 64 bytes. Ed25519 verification of the signature base against that key succeeds.

**Step 7. Audience.** `aud` is `"prov-test-1"`. A verifier configured with provider id `prov-test-1` continues; one configured with any other id rejects with `WRONG_PROVIDER`.

**Step 8. Nonce.** `AQEBAQEBAQEBAQEBAQEBAQ` is new. Remember it until `expires + 60 = 1760700360`. A second request with the same nonce is `REPLAYED`.

The seed behind this key is public and for tests only. Real traffic uses the keys in the JWKS URLs above.

## Code

Each snippet takes the request parts, a JWKS and your provider id(s), and returns `OK` or a reason code. Turn a reason code into the `401` response described above. The Node, Python and Go versions have been run against `test-vectors/v1.json` and `test-vectors/negative.json`.

In all three: pass the **target** as sent (path plus query), the **raw** body, and `now` in unix seconds. `seen` is where you keep nonces. A set in memory is fine for one process. With several instances, use a shared store such as Redis (`SET key 1 NX EX <seconds>`), and remove old entries after `expires + 60`.

### Node.js (`node:crypto`, no packages)

```js
import { createHash, createPublicKey, verify } from "node:crypto";

const COMPONENTS = ["@method", "@authority", "@path", "@query"];

// req: { method, host, target, headers (lowercase names), body (Buffer or undefined) }
// jwks: { keys: [...] }  now: unix seconds.  providers: your provider id(s), e.g. ["your-provider-id"].
// Returns "OK" or a reason code.
export function verifyAssay(req, jwks, now, providers, seen = new Set()) {
  const si = req.headers["signature-input"], sg = req.headers["signature"];
  if (!si || !sg) return "MISSING";
  const m = /^assay=(\(([^)]*)\))(;.*)$/.exec(si);
  const s = /^assay=:([A-Za-z0-9+/=]+):$/.exec(sg);
  if (!m || !s) return "MALFORMED";
  const p = Object.fromEntries([...m[3].matchAll(/;(\w+)=("[^"]*"|\d+)/g)].map(
    (x) => [x[1], x[2].replace(/^"|"$/g, "")]));
  if (p.tag !== "assay-request") return "WRONG_TAG";
  if (p.alg !== "ed25519" || !/^\d+$/.test(p.created ?? "") || !/^\d+$/.test(p.expires ?? "") ||
      !p.nonce || !p.keyid) return "MALFORMED";
  const names = [...m[2].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  const covered = names.includes("content-digest");
  const want = [...COMPONENTS, ...(covered ? ["content-digest"] : []), "x-assay-call-id"];
  if (names.join() !== want.join() || (req.body?.length && !covered)) return "MALFORMED";
  if (req.target.startsWith("//") || !req.target.startsWith("/")) return "MALFORMED";
  const digest = "sha-256=:" + createHash("sha256").update(req.body ?? "").digest("base64") + ":";
  if (covered && req.headers["content-digest"] !== digest) return "DIGEST_MISMATCH";
  const created = +p.created, expires = +p.expires;
  if (expires < created || expires - created > 300 || now < created - 60 || now > expires + 60) return "EXPIRED";
  const i = req.target.indexOf("?");
  const path = (i < 0 ? req.target : req.target.slice(0, i)) || "/";
  const query = "?" + (i < 0 ? "" : req.target.slice(i + 1));
  const value = { "@method": req.method.toUpperCase(), "@authority": req.host.toLowerCase(),
    "@path": path, "@query": query, "content-digest": digest,
    "x-assay-call-id": req.headers["x-assay-call-id"] };
  const base = names.map((n) => `"${n}": ${value[n]}`).join("\n") +
    `\n"@signature-params": ${m[1]}${m[3]}`;
  const jwk = jwks.keys.find((k) => k.kid === p.keyid);
  if (!jwk) return "UNKNOWN_KEY";
  const key = createPublicKey({ key: jwk, format: "jwk" });
  if (!verify(null, Buffer.from(base), key, Buffer.from(s[1], "base64"))) return "BAD_SIGNATURE";
  const aud = /;aud="([^"]*)"/.exec(m[3])?.[1]; // must be a quoted string
  if (aud === undefined || !providers.includes(aud)) return "WRONG_PROVIDER";
  if (seen.has(p.nonce)) return "REPLAYED";
  seen.add(p.nonce); // also delete it after expires + 60 seconds
  return "OK";
}
```

### Python (`cryptography`)

```python
import base64, hashlib, re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

COMPONENTS = ["@method", "@authority", "@path", "@query"]

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def verify_assay(method, host, target, headers, body, jwks, now, seen, providers):
    """headers: lowercase names. body: bytes or None. providers: your provider id(s),
    for example {"your-provider-id"}. Returns "OK" or a reason code."""
    si, sg = headers.get("signature-input"), headers.get("signature")
    if not si or not sg:
        return "MISSING"
    m = re.fullmatch(r'assay=(\(([^)]*)\))(;.*)', si)
    s = re.fullmatch(r'assay=:([A-Za-z0-9+/=]+):', sg)
    if not m or not s:
        return "MALFORMED"
    p = {k: v.strip('"') for k, v in re.findall(r';(\w+)=("[^"]*"|\d+)', m.group(3))}
    if p.get("tag") != "assay-request":
        return "WRONG_TAG"
    if (p.get("alg") != "ed25519" or not p.get("created", "").isdigit()
            or not p.get("expires", "").isdigit() or not p.get("nonce") or not p.get("keyid")):
        return "MALFORMED"
    names = re.findall(r'"([^"]+)"', m.group(2))
    covered = "content-digest" in names
    want = COMPONENTS + (["content-digest"] if covered else []) + ["x-assay-call-id"]
    if not headers.get("x-assay-call-id"):
        return "MALFORMED"
    if names != want or (body and not covered) or target.startswith("//") or not target.startswith("/"):
        return "MALFORMED"
    digest = "sha-256=:" + base64.b64encode(hashlib.sha256(body or b"").digest()).decode() + ":"
    if covered and headers.get("content-digest") != digest:
        return "DIGEST_MISMATCH"
    created, expires = int(p["created"]), int(p["expires"])
    if expires < created or expires - created > 300 or now < created - 60 or now > expires + 60:
        return "EXPIRED"
    path, _, query = target.partition("?")
    value = {"@method": method.upper(), "@authority": host.lower(), "@path": path or "/",
             "@query": "?" + query, "content-digest": digest,
             "x-assay-call-id": headers.get("x-assay-call-id")}
    base = "\n".join(f'"{n}": {value[n]}' for n in names) + f'\n"@signature-params": {m.group(1)}{m.group(3)}'
    jwk = next((k for k in jwks["keys"] if k["kid"] == p["keyid"]), None)
    if jwk is None:
        return "UNKNOWN_KEY"
    try:
        Ed25519PublicKey.from_public_bytes(b64d(jwk["x"])).verify(base64.b64decode(s.group(1)), base.encode())
    except InvalidSignature:
        return "BAD_SIGNATURE"
    aud = re.search(r';aud="([^"]*)"', m.group(3))  # must be a quoted string
    if aud is None or aud.group(1) not in providers:
        return "WRONG_PROVIDER"
    if p["nonce"] in seen:
        return "REPLAYED"
    seen.add(p["nonce"])  # also delete it after expires + 60 seconds
    return "OK"
```

### Go (standard library)

```go
package assayverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	siRe = regexp.MustCompile(`^assay=(\(([^)]*)\))(;.*)$`)
	sgRe = regexp.MustCompile(`^assay=:([A-Za-z0-9+/=]+):$`)
	pRe  = regexp.MustCompile(`;(\w+)=("[^"]*"|\d+)`)
	nRe  = regexp.MustCompile(`"([^"]+)"`)
	aRe  = regexp.MustCompile(`;aud="([^"]*)"`)
)

// target: the request target as sent (r.RequestURI), body: the raw bytes (nil if none).
// keys: kid -> public key, from the JWKS ("x" is base64url). Every key must be a
// 32-byte Ed25519 public key: ed25519.Verify panics on any other length.
// providers: your provider id(s) -> true. Returns "OK" or a reason code.
func Verify(r *http.Request, target string, body []byte, keys map[string]ed25519.PublicKey, providers map[string]bool, now int64, seen map[string]bool) string {
	si, sg := r.Header.Get("Signature-Input"), r.Header.Get("Signature")
	if si == "" || sg == "" {
		return "MISSING"
	}
	m, s := siRe.FindStringSubmatch(si), sgRe.FindStringSubmatch(sg)
	if m == nil || s == nil {
		return "MALFORMED"
	}
	p := map[string]string{}
	for _, x := range pRe.FindAllStringSubmatch(m[3], -1) {
		p[x[1]] = strings.Trim(x[2], `"`)
	}
	if p["tag"] != "assay-request" {
		return "WRONG_TAG"
	}
	created, e1 := strconv.ParseInt(p["created"], 10, 64)
	expires, e2 := strconv.ParseInt(p["expires"], 10, 64)
	if p["alg"] != "ed25519" || e1 != nil || e2 != nil || p["nonce"] == "" || p["keyid"] == "" {
		return "MALFORMED"
	}
	var names []string
	for _, x := range nRe.FindAllStringSubmatch(m[2], -1) {
		names = append(names, x[1])
	}
	covered := strings.Contains(m[2], `"content-digest"`)
	want := "@method @authority @path @query x-assay-call-id"
	if covered {
		want = "@method @authority @path @query content-digest x-assay-call-id"
	}
	if strings.Join(names, " ") != want || (len(body) > 0 && !covered) ||
		strings.HasPrefix(target, "//") || !strings.HasPrefix(target, "/") {
		return "MALFORMED"
	}
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if covered && r.Header.Get("Content-Digest") != digest {
		return "DIGEST_MISMATCH"
	}
	if expires < created || expires-created > 300 || now < created-60 || now > expires+60 {
		return "EXPIRED"
	}
	path, query, _ := strings.Cut(target, "?")
	if path == "" {
		path = "/"
	}
	value := map[string]string{
		"@method": strings.ToUpper(r.Method), "@authority": strings.ToLower(r.Host),
		"@path": path, "@query": "?" + query, "content-digest": digest,
		"x-assay-call-id": r.Header.Get("X-Assay-Call-Id"),
	}
	lines := make([]string, 0, len(names)+1)
	for _, n := range names {
		lines = append(lines, fmt.Sprintf(`"%s": %s`, n, value[n]))
	}
	lines = append(lines, `"@signature-params": `+m[1]+m[3])
	key, ok := keys[p["keyid"]]
	if !ok {
		return "UNKNOWN_KEY"
	}
	sig, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil || !ed25519.Verify(key, []byte(strings.Join(lines, "\n")), sig) {
		return "BAD_SIGNATURE"
	}
	if a := aRe.FindStringSubmatch(m[3]); a == nil || !providers[a[1]] { // must be a quoted string
		return "WRONG_PROVIDER"
	}
	if seen[p["nonce"]] {
		return "REPLAYED"
	}
	seen[p["nonce"]] = true // also delete it after expires + 60 seconds
	return "OK"
}
```

Note for Go: `r.Host` is the `Host` header as the client sent it. Use it as is (lowercased); do not add or strip a port.

## Fetching the keys

- Fetch the JWKS over HTTPS with a **5 second timeout**.
- Cache it for **1 hour**.
- When you see a `keyid` that is not in your cache, fetch again, but **at most once every 60 seconds**. This is how you pick up a key rotation.
- If a fetch **fails**, do not try again for **5 seconds**. During that time, use the keys you already have. If you have none, answer `UNKNOWN_KEY`. After 5 seconds, try again. This stops a down key server from slowing every request.
- Never skip verification because the key server is down.

## Check your work

Run every case in `test-vectors/v1.json` (all must verify) and `test-vectors/negative.json` (each must give its `expectedReason`). The file shapes are described in [overview.md](overview.md#test-vectors). If the worked example above passes but others fail, check `@authority` (the `Host` header as received, or your public host behind a proxy) and header name case first.
