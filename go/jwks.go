package assayverify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// JWKSURLProduction is the default key set URL.
	JWKSURLProduction = "https://api.goassay.ai/.well-known/assay-request-keys.json"
	// JWKSURLTestnet is the key set URL for Environment "testnet".
	JWKSURLTestnet = "https://api-dev.goassay.ai/.well-known/assay-request-keys.json"

	jwksCacheTTL         = 3600 // seconds
	jwksRefetchMin       = 60
	jwksFailureBackoff   = 5
	jwksFetchTimeout     = 5 * time.Second
	jwksMaxResponseBytes = 1 << 20
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
}

func resolveJWKSURL(o Options) string {
	if o.JWKSURL != "" {
		return o.JWKSURL
	}
	if o.Environment == "testnet" {
		return JWKSURLTestnet
	}
	return JWKSURLProduction
}

// parseKeys keeps only well-formed Ed25519 keys: ed25519.Verify panics on a
// public key of the wrong length, so anything but 32 bytes is skipped.
func parseKeys(raw []json.RawMessage) map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	for _, r := range raw {
		var k jwk
		if json.Unmarshal(r, &k) != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" || k.X == "" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	return keys
}

func parseJWKS(data []byte) ([]json.RawMessage, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Keys == nil {
		return nil, fmt.Errorf("jwks: missing keys array")
	}
	return doc.Keys, nil
}

// jwksCache caches the key set. The clock (unix seconds) is passed per call.
type jwksCache struct {
	url    string
	client *http.Client

	mu       sync.Mutex // held during a fetch, so a kid is never declared unknown mid-load
	keys     map[string]ed25519.PublicKey
	loadedAt *int64
	failedAt *int64
}

func (c *jwksCache) getKey(kid string, now int64) ed25519.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadedAt != nil && now-*c.loadedAt < jwksCacheTTL {
		if k, ok := c.keys[kid]; ok {
			return k
		}
		// Unknown kid: refetch at most once per 60 s.
		if now-*c.loadedAt < jwksRefetchMin {
			return nil
		}
	}
	// After a failed fetch, wait 5 s before trying again (cached keys stay usable).
	if c.failedAt != nil && now-*c.failedAt < jwksFailureBackoff {
		return c.keys[kid]
	}
	if keys, err := c.fetch(); err != nil {
		c.failedAt = &now
	} else {
		c.keys = keys
		c.loadedAt = &now
		c.failedAt = nil
	}
	return c.keys[kid]
}

func (c *jwksCache) fetch() (map[string]ed25519.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("jwks http %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, jwksMaxResponseBytes))
	if err != nil {
		return nil, err
	}
	raw, err := parseJWKS(data)
	if err != nil {
		return nil, err
	}
	return parseKeys(raw), nil
}

// Caches are shared per resolved URL (and HTTP client), so building several
// verifiers does not multiply fetches.
type cacheKey struct {
	url    string
	client *http.Client
}

var (
	sharedCachesMu sync.Mutex
	sharedCaches   = map[cacheKey]*jwksCache{}
)

func sharedJWKSCache(url string, client *http.Client) *jwksCache {
	sharedCachesMu.Lock()
	defer sharedCachesMu.Unlock()
	k := cacheKey{url, client}
	if c, ok := sharedCaches[k]; ok {
		return c
	}
	hc := client
	if hc == nil {
		hc = &http.Client{Timeout: jwksFetchTimeout}
	}
	c := &jwksCache{url: url, client: hc}
	sharedCaches[k] = c
	return c
}
