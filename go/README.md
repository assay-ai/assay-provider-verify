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

verify, err := assayverify.Middleware(assayverify.Options{
	Providers: []string{"your-provider-id"}, // your Assay provider id, shown in the portal (required)
}) // production keys
if err != nil {
	log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8080", verify(mux)))
```

`Providers` is required. Assay signs requests for every provider with the same keys, so a request it
signed for another provider is rejected with `WRONG_PROVIDER`.
It works with any router that takes an `http.Handler`. Testnet keys: `Options{Environment: "testnet"}`.
Behind a proxy that rewrites `Host`: `Options{Authority: "api.example.com"}`. With more than one
instance, plug a shared `ReplayStore` (see `example_redis_test.go`).

## Upgrading from 0.1

0.2.0 makes `Options.Providers` required (`New` and `Middleware` return `ErrNoProvider` without it),
adds the reject reason `WRONG_PROVIDER`, and changes `Verify` to return `(Result, error)`. Set
Providers to your Assay provider id (shown in the portal). See the
[changelog](https://github.com/assay-ai/assay-provider-verify/blob/main/CHANGELOG.md).

## Documentation

- [Go guide](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/level-1-go.md): middleware, options, the verify function, Redis, proxies, local testing.
- [Troubleshooting](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/troubleshooting.md): what each reject reason means.
- [How the signature works](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/overview.md).

## License

MIT, see [LICENSE](LICENSE).
