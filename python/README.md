# goassay-provider-verify

Verify that a request to your API really comes from [Assay](https://goassay.ai). Assay signs every
request it forwards with an Ed25519 signature (HTTP Message Signatures, RFC 9421 style); this package
checks it with ASGI and WSGI middleware. The only runtime dependency is `cryptography`. Python 3.9 or
newer (the test suite runs on 3.10+).

```sh
pip install goassay-provider-verify
```

Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your app unchanged,
with the full body still readable.

## One line per framework

```python
from goassay_provider_verify import AssayVerifyMiddleware, AssayVerifyWSGI

app.add_middleware(AssayVerifyMiddleware)                # FastAPI / Starlette (ASGI)
app.wsgi_app = AssayVerifyWSGI(app.wsgi_app)             # Flask (WSGI)
application = AssayVerifyWSGI(get_wsgi_application())    # Django, in wsgi.py
```

Without a framework, call the verifier yourself:

```python
from goassay_provider_verify import Verifier

result = Verifier().verify(method, url, headers, body)  # url = path + query; body = raw bytes or None
if not result.ok:
    print(result.reason)
```

Testnet keys: pass `environment="testnet"`. Behind a proxy that rewrites `Host`, pass
`authority="api.example.com"`. With more than one instance, use `redis_replay_store`
(`pip install "goassay-provider-verify[redis]"`).

## Documentation

- [Python guide](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/level-1-python.md): middleware, options, Redis, proxies, local testing.
- [Troubleshooting](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/troubleshooting.md): what each reject reason means.
- [How the signature works](https://github.com/assay-ai/assay-provider-verify/blob/main/docs/overview.md).

## License

MIT, see [LICENSE](LICENSE).
