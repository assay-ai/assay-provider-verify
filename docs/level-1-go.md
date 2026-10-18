# Level 1 - Go

Verify Assay request signatures with a few lines of `net/http` middleware. The module uses only the
Go standard library (Go 1.21 or newer).

```sh
go get github.com/assay-ai/assay-provider-verify/go
```

Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your handler
unchanged, with `r.Body` restored so the full body is still readable.

## Middleware

```go
package main

import (
	"log"
	"net/http"

	assayverify "github.com/assay-ai/assay-provider-verify/go"
)

func main() {
	verify, err := assayverify.Middleware(assayverify.Options{}) // production keys
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/search", func(w http.ResponseWriter, r *http.Request) { /* ... */ })
	log.Fatal(http.ListenAndServe(":8080", verify(mux)))
}
```

It works with any router that takes an `http.Handler` (chi, gorilla/mux, Gin through an adapter).
Mount it before anything that reads the body. The middleware buffers the body, verifies, then hands
the same bytes to your handler.

## Options

| Field | Default | Meaning |
|---|---|---|
| `Environment` | `"production"` | `"testnet"` selects the testnet key set |
| `JWKSURL` | per environment | Override the key set URL |
| `Authority` | `Host` header | Public host (`:port` if not the scheme default) when a proxy rewrites `Host` |
| `ReplayStore` | in-memory, process-wide | See Redis below |
| `ClockSkew` | `60s` | Tolerance around `created`/`expires` |
| `Now` | `time.Now` | Clock (tests) |
| `HTTPClient` | 5 s timeout | Client used to fetch the key set |
| `JWKS` | none | Static key set (`{"keys":[...]}` as JSON bytes); disables fetching |
| `MaxBodyBytes` | `5242880` | Bodies are buffered before authentication; larger ones get `413 {"error":"payload_too_large"}` without verifying |

Keys are fetched with a 5 s timeout, cached for one hour, and shared by all verifiers for the same
URL. An unknown `kid` triggers at most one refetch per 60 s; after a failed fetch the next attempt
waits 5 s. `ClockSkew: 0` means the 60 s default. Caches are keyed by URL and `*http.Client`, so build one client and reuse it. If the replay store returns an error, the middleware answers `500` and the request is
not served (fail closed).

## Without the middleware

```go
v, err := assayverify.New(assayverify.Options{})
if err != nil { /* bad Options */ }

body, _ := io.ReadAll(r.Body) // the raw bytes; nil or empty when there is none
keyID, callID, reason, err := v.Verify(r, body)
switch {
case err != nil:
	// replay store failure: do not serve the request
case reason != "":
	// rejected; reason is an assayverify.RejectReason such as assayverify.ReasonBadSignature
default:
	// accepted: keyID, callID
}
```

`Verify` reads the path and query from `r.RequestURI` (the request target as the client sent it,
never resolved or normalised), so use it with requests received by `net/http` servers. Targets that
start with `//` or do not start with `/` are rejected as `MALFORMED`. Header names match
case-insensitively.

## Multiple instances and Redis

The default replay store is in memory (LRU, 100 000 entries), and one instance is shared by every
verifier in the process. With more than one server instance, pass a shared store so a nonce replayed
against another instance is still caught. Implement the interface:

```go
type ReplayStore interface {
	// CheckAndStore reports true when the nonce was not seen before and is now stored for ttl.
	CheckAndStore(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
}
```

With Redis that is one `SET key 1 NX EX <ttl>`. A complete example for go-redis (not a dependency of
this module) is in [`go/example_redis_test.go`](../go/example_redis_test.go). Errors must be returned,
not swallowed.

## Proxies and the `Authority` option

The signature covers `@authority`, the host the caller used. If a proxy rewrites `Host`, set the
public host explicitly:

```go
assayverify.Middleware(assayverify.Options{Authority: "api.example.com"})
```

## Testing locally with the vectors

`test-vectors/v1.json` holds signed requests and a TEST ONLY public key. Inject it and pin the clock to
the vector's `created` time so nothing is fetched and nothing expires:

```go
mw, _ := assayverify.Middleware(assayverify.Options{
	JWKS:      []byte(`{"keys":[` + publicKeyJwk + `]}`),
	Now:       func() time.Time { return time.Unix(created, 0) },
	Authority: "api.example.test",
})
```

Changing one byte of the body returns `DIGEST_MISMATCH`. Replaying the same request returns
`REPLAYED`. See `go/verify_test.go` and `go/middleware_test.go` for working tests.
