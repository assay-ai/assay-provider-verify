# Level 1 - Python

Verify Assay request signatures with a few lines of middleware. The only runtime dependency is
`cryptography`; frameworks and Redis are optional.

```sh
pip install goassay-provider-verify
```

Python 3.9 or newer. Rejected requests get `401`, `content-type: application/json` and
`{"error":"invalid_assay_signature","reason":"<CODE>"}`. Accepted requests reach your handler
unchanged, with the full body still readable.

## FastAPI / Starlette (ASGI)

```python
from goassay_provider_verify import AssayVerifyMiddleware

app.add_middleware(AssayVerifyMiddleware)
```

The middleware buffers the body, verifies, then replays the same bytes to your app, so
`await request.json()` works as usual. Non-HTTP scopes (lifespan, websocket) pass through.

## Flask / Django (WSGI)

```python
from goassay_provider_verify import AssayVerifyWSGI

app.wsgi_app = AssayVerifyWSGI(app.wsgi_app)          # Flask
# Django: in wsgi.py -> application = AssayVerifyWSGI(get_wsgi_application())
```

The middleware reads the body, verifies, then replaces `wsgi.input` with the buffered bytes and sets
`CONTENT_LENGTH`.

## Options

Pass options as keyword arguments to either middleware, or to `Verifier` directly:

| Option | Default | Meaning |
|---|---|---|
| `environment` | `"production"` | `"testnet"` selects the testnet key set |
| `jwks_url` | per environment | Override the key set URL |
| `authority` | `Host` header | Public host (`:port` if not the scheme default) when a proxy rewrites `Host` |
| `replay_store` | in-memory, process-wide | See Redis below |
| `clock_skew` | `60` | Seconds of tolerance around `created`/`expires` |
| `now` | system clock | Callable returning unix seconds (tests) |
| `jwks` | none | Static key set (`{"keys": [...]}`); disables fetching |
| `max_body_bytes` | `5242880` | Bodies are buffered before authentication; larger ones get `413 {"error":"payload_too_large"}` without verifying |

Keys are fetched with `urllib` (5 s timeout), cached for one hour, and shared by all verifiers for
the same URL. An unknown `kid` triggers at most one refetch per 60 s; after a failed fetch the next
attempt waits 5 s.

## Without a framework

```python
from goassay_provider_verify import Verifier

verifier = Verifier()
result = verifier.verify(method, url, headers, body)   # body: bytes, or None when the request has none
if not result.ok:
    ...  # result.reason is a RejectReason, for example RejectReason.BAD_SIGNATURE
else:
    ...  # result.key_id, result.call_id
```

`url` is the request target as sent (`/path?q=1`) or an absolute URL. Targets starting with `//` or
not starting with `/` are rejected as `MALFORMED`. `headers` is any mapping; names are matched
case-insensitively.

## Multiple instances and Redis

The default replay store is in memory (LRU, 100 000 entries) and per process. With more than one
instance, use a shared store so a nonce replayed against another instance is still caught:

```python
import redis
from goassay_provider_verify import AssayVerifyMiddleware, redis_replay_store

r = redis.Redis.from_url(os.environ["REDIS_URL"])
app.add_middleware(AssayVerifyMiddleware, replay_store=redis_replay_store(r))  # key prefix "assay:nonce:"
```

`redis_replay_store(client, prefix="assay:nonce:")` uses `SET key 1 NX EX <ttl>` and works with any
redis-py compatible client (`pip install "goassay-provider-verify[redis]"`). Redis errors are not
swallowed: verification fails closed.

Use a sync client (`redis.Redis`, not `redis.asyncio.Redis`), also under FastAPI/Starlette. The ASGI
middleware runs verification (the JWKS fetch and the replay check) in a worker thread, so the sync
Redis calls and a slow JWKS fetch never block the event loop.

## Proxies and the `authority` option

The signature covers `@authority`, the host the caller used. If a proxy rewrites `Host`, set the
public host explicitly:

```python
app.add_middleware(AssayVerifyMiddleware, authority="api.example.com")
```

## Testing locally with the vectors

`test-vectors/v1.json` holds signed requests and a TEST ONLY public key. Inject it and pin the clock to
the vector's `created` time so nothing is fetched and nothing expires:

```python
v1 = json.load(open("test-vectors/v1.json"))
c = v1["cases"][0]
app.add_middleware(
    AssayVerifyMiddleware,
    jwks={"keys": [v1["publicKeyJwk"]]},
    now=lambda: c["params"]["created"],
    authority="api.example.test",
)
# Send c["request"] with the headers from c["request"]["headers"] and c["expected"]["headers"].
```

Changing one byte of the body returns `DIGEST_MISMATCH`. Replaying the same request returns `REPLAYED`.
See `python/tests/test_middleware.py` for working FastAPI and Flask examples.
