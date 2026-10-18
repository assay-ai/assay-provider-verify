# assay-provider-verify for Go

Verify that a request to your API really comes from [Assay](https://goassay.ai). Assay signs every
request it forwards with an Ed25519 signature (HTTP Message Signatures, RFC 9421 style); this module
checks it with `net/http` middleware. Standard library only, Go 1.21 or newer.

```sh
go get github.com/assay-ai/assay-provider-verify/go
```

Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your handler
unchanged, with `r.Body` restored.

## Middleware

```go
import assayverify "github.com/assay-ai/assay-provider-verify/go"

verify, err := assayverify.Middleware(assayverify.Options{}) // production keys
if err != nil {
	log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", verify(mux)))
```

It works with any router that takes an `http.Handler`. Testnet keys: `Options{Environment: "testnet"}`.
Behind a proxy that rewrites `Host`: `Options{Authority: "api.example.com"}`. With more than one
instance, plug a shared `ReplayStore` (see `example_redis_test.go`).

## Documentation

- [Go guide](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/level-1-go.md): middleware, options, the verify function, Redis, proxies, local testing.
- [Troubleshooting](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/troubleshooting.md): what each reject reason means.
- [How the signature works](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/overview.md).

## License

MIT, see [LICENSE](LICENSE).
