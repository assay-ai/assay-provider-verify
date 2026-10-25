// Package assayverify verifies Assay's Ed25519 request signatures (RFC 9421
// style, label "assay") using only the standard library, and ships a net/http
// middleware.
package assayverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RejectReason is a signature failure code.
type RejectReason string

const (
	ReasonMissing        RejectReason = "MISSING"
	ReasonMalformed      RejectReason = "MALFORMED"
	ReasonWrongTag       RejectReason = "WRONG_TAG"
	ReasonExpired        RejectReason = "EXPIRED"
	ReasonDigestMismatch RejectReason = "DIGEST_MISMATCH"
	ReasonUnknownKey     RejectReason = "UNKNOWN_KEY"
	ReasonBadSignature   RejectReason = "BAD_SIGNATURE"
	ReasonWrongProvider  RejectReason = "WRONG_PROVIDER"
	ReasonReplayed       RejectReason = "REPLAYED"
)

// DefaultMaxBodyBytes is the default cap for bodies buffered by the middleware.
const DefaultMaxBodyBytes = 5_242_880

// ErrNoProvider is returned by New and Middleware when Options.Providers is empty.
var ErrNoProvider = errors.New("assayverify: Options.Providers is required (your Assay provider id, shown in the portal)")

var providerIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Options configures a Verifier or the middleware.
type Options struct {
	// Providers is REQUIRED: your Assay provider id (shown in the portal), or
	// several. Only requests signed for one of these providers (the "aud"
	// signature parameter) are accepted; others get WRONG_PROVIDER.
	Providers []string
	// JWKSURL overrides the key set URL (default: per Environment).
	JWKSURL string
	// Environment is "production" (default) or "testnet".
	Environment string
	// Authority overrides the @authority taken from the Host header.
	Authority string
	// ReplayStore defaults to one in-memory store shared by the whole process.
	ReplayStore ReplayStore
	// ClockSkew is the tolerance around created/expires (default 60s).
	ClockSkew time.Duration
	// Now returns the current time (default time.Now).
	Now func() time.Time
	// HTTPClient fetches the key set (default: 5 s timeout).
	HTTPClient *http.Client
	// JWKS is a static key set ({"keys":[...]}); disables fetching.
	JWKS []byte
	// MaxBodyBytes caps the body the middleware buffers (default 5 MiB).
	MaxBodyBytes int64
}

// Verifier checks request signatures. It is safe for concurrent use.
type Verifier struct {
	opts      Options
	providers map[string]struct{}
	replay    ReplayStore
	cache     *jwksCache
	static    map[string]ed25519.PublicKey
	now       func() time.Time
	skew      int64
}

var defaultReplay = NewMemoryReplayStore(100_000)

// New builds a Verifier. Without a ReplayStore it uses a process-wide in-memory
// one; key set caches are shared per URL. It fails with ErrNoProvider when
// Options.Providers is empty, and with an error for an invalid provider id.
func New(opts Options) (*Verifier, error) {
	if len(opts.Providers) == 0 {
		return nil, ErrNoProvider
	}
	providers := make(map[string]struct{}, len(opts.Providers))
	for _, p := range opts.Providers {
		if !providerIDRe.MatchString(p) {
			return nil, fmt.Errorf("assayverify: invalid provider id %q", p)
		}
		providers[p] = struct{}{}
	}
	v := &Verifier{opts: opts, providers: providers, replay: opts.ReplayStore, now: opts.Now, skew: 60}
	if v.replay == nil {
		v.replay = defaultReplay
	}
	if v.now == nil {
		v.now = time.Now
	}
	if opts.ClockSkew > 0 {
		v.skew = int64(opts.ClockSkew / time.Second)
	}
	if opts.JWKS != nil {
		raw, err := parseJWKS(opts.JWKS)
		if err != nil {
			return nil, err
		}
		v.static = parseKeys(raw)
	} else {
		v.cache = sharedJWKSCache(resolveJWKSURL(opts), opts.HTTPClient)
	}
	return v, nil
}

var absoluteRe = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)

type target struct {
	path, query, host string
}

// parseTarget splits the request target as sent; it never resolves or
// normalises origin-form targets. Absolute URLs also supply a fallback host.
func parseTarget(raw string) (target, bool) {
	if strings.HasPrefix(raw, "//") {
		return target{}, false
	}
	if absoluteRe.MatchString(raw) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return target{}, false
		}
		path := u.EscapedPath()
		if strings.HasPrefix(path, "//") {
			return target{}, false
		}
		if path == "" {
			path = "/"
		}
		host := strings.ToLower(u.Host)
		switch {
		case u.Scheme == "http" || u.Scheme == "HTTP":
			host = strings.TrimSuffix(host, ":80")
		case u.Scheme == "https" || u.Scheme == "HTTPS":
			host = strings.TrimSuffix(host, ":443")
		}
		return target{path: path, query: u.RawQuery, host: host}, true
	}
	if !strings.HasPrefix(raw, "/") {
		return target{}, false
	}
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	path, query, _ := strings.Cut(raw, "?")
	return target{path: path, query: query}, true
}

func headerValue(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

var expectedBase = []string{"@method", "@authority", "@path", "@query"}

// Result is the outcome of Verify. Reason is empty when the request is
// accepted; KeyID, CallID and ProviderID are set only then.
type Result struct {
	KeyID      string
	CallID     string
	ProviderID string // the matched entry of Options.Providers
	Reason     RejectReason
}

// OK reports whether the request was accepted.
func (r Result) OK() bool { return r.Reason == "" }

// Verify checks the request's signature. body is the raw body (nil or empty
// when there is none). err is non-nil only when the replay store fails (fail
// closed: treat as an error, not as a rejection).
func (v *Verifier) Verify(r *http.Request, body []byte) (Result, error) {
	reject := func(x RejectReason) (Result, error) { return Result{Reason: x}, nil }

	// 1. Headers.
	sigInputHeader := strings.TrimSpace(headerValue(r.Header, "Signature-Input"))
	sigHeader := strings.TrimSpace(headerValue(r.Header, "Signature"))
	if sigInputHeader == "" || sigHeader == "" {
		return reject(ReasonMissing)
	}
	inputs, e1 := parseDictionary(sigInputHeader)
	sigs, e2 := parseDictionary(sigHeader)
	if e1 != nil || e2 != nil {
		return reject(ReasonMalformed)
	}
	in, ok1 := inputs["assay"]
	sm, ok2 := sigs["assay"]
	if !ok1 || !ok2 {
		return reject(ReasonMissing)
	}
	if sm.item == nil || sm.item.kind != kindBytes {
		return reject(ReasonMalformed)
	}
	signature, e := base64.RawStdEncoding.DecodeString(strings.TrimRight(sm.item.s, "="))
	if e != nil {
		return reject(ReasonMalformed)
	}

	// 2. Parameters.
	if !in.isList {
		return reject(ReasonMalformed)
	}
	intParam := func(n string) (int64, bool) {
		p, ok := in.params[n]
		return p.n, ok && p.kind == kindInt
	}
	strParam := func(n string) string {
		if p, ok := in.params[n]; ok && p.kind == kindString {
			return p.s
		}
		return ""
	}
	created, okC := intParam("created")
	expires, okE := intParam("expires")
	nonce, kid := strParam("nonce"), strParam("keyid")
	if tag, ok := in.params["tag"]; !ok || tag.kind != kindString || tag.s != "assay-request" {
		return reject(ReasonWrongTag)
	}
	if strParam("alg") != "ed25519" || !okC || !okE || nonce == "" || kid == "" {
		return reject(ReasonMalformed)
	}

	// 3. Components and digest.
	withDigest := false
	for _, c := range in.list {
		if c == "content-digest" {
			withDigest = true
		}
	}
	expected := append([]string{}, expectedBase...)
	if withDigest {
		expected = append(expected, "content-digest")
	}
	expected = append(expected, "x-assay-call-id")
	if len(in.list) != len(expected) {
		return reject(ReasonMalformed)
	}
	for i, c := range in.list {
		if c != expected[i] {
			return reject(ReasonMalformed)
		}
	}
	if !withDigest && len(body) > 0 {
		return reject(ReasonMalformed)
	}
	var digestValue string
	if withDigest {
		digestValue = strings.TrimSpace(headerValue(r.Header, "Content-Digest"))
		if digestValue == "" {
			return reject(ReasonMissing)
		}
		dm, e := parseDictionary(digestValue)
		if e != nil {
			return reject(ReasonMalformed)
		}
		sum := sha256.Sum256(body)
		item := dm["sha-256"].item
		if item == nil || item.kind != kindBytes || item.s != base64.StdEncoding.EncodeToString(sum[:]) {
			return reject(ReasonDigestMismatch)
		}
	}

	// 4. Time window.
	t := v.now().Unix()
	if expires < created || expires-created > 300 || t < created-v.skew || t > expires+v.skew {
		return reject(ReasonExpired)
	}

	// 5. Signature base.
	call := strings.TrimSpace(headerValue(r.Header, "X-Assay-Call-Id"))
	if call == "" {
		return reject(ReasonMalformed)
	}
	raw := r.RequestURI
	if raw == "" && r.URL != nil {
		raw = r.URL.RequestURI()
	}
	tg, ok := parseTarget(raw)
	if !ok {
		return reject(ReasonMalformed)
	}
	authority := strings.ToLower(v.opts.Authority)
	if authority == "" {
		authority = strings.ToLower(strings.TrimSpace(r.Host))
	}
	if authority == "" {
		authority = tg.host
	}
	if authority == "" {
		return reject(ReasonMalformed)
	}
	path := tg.path
	if path == "" {
		path = "/"
	}
	lines := []string{
		`"@method": ` + strings.ToUpper(r.Method),
		`"@authority": ` + authority,
		`"@path": ` + path,
		`"@query": ?` + tg.query,
	}
	if withDigest {
		lines = append(lines, `"content-digest": `+digestValue)
	}
	lines = append(lines, `"x-assay-call-id": `+call, `"@signature-params": `+in.raw)
	base := []byte(strings.Join(lines, "\n"))

	// 6. Key lookup and signature.
	var key ed25519.PublicKey
	if v.static != nil {
		key = v.static[kid]
	} else {
		key = v.cache.getKey(kid, t)
	}
	if len(key) != ed25519.PublicKeySize {
		return reject(ReasonUnknownKey)
	}
	if !ed25519.Verify(key, base, signature) {
		return reject(ReasonBadSignature)
	}

	// 7. Audience: only after the signature holds, so unsigned probes learn nothing.
	aud, ok := in.params["aud"]
	if !ok || aud.kind != kindString {
		return reject(ReasonWrongProvider)
	}
	if _, ok := v.providers[aud.s]; !ok {
		return reject(ReasonWrongProvider)
	}

	// 8. Replay.
	ttl := expires + v.skew - t
	if ttl < 1 {
		ttl = 1
	}
	fresh, err := v.replay.CheckAndStore(r.Context(), nonce, time.Duration(ttl)*time.Second)
	if err != nil {
		return Result{}, err
	}
	if !fresh {
		return reject(ReasonReplayed)
	}
	return Result{KeyID: kid, CallID: call, ProviderID: aud.s}, nil
}
