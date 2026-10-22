import base64
import json
import urllib.error
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from goassay_provider_verify import MemoryReplayStore, RejectReason, Verifier, jwks as jwks_mod
from goassay_provider_verify.replay import redis_replay_store

V1 = json.loads((Path(__file__).resolve().parents[2] / "test-vectors" / "v1.json").read_text())
SEED = bytes.fromhex(V1["seedHex"])
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
JWK = V1["publicKeyJwk"]


def sign(method="GET", target="/p?x=1", host="api.example.test", created=1000, expires=None, call_id="c1",
         body=None, nonce="n1", kid="test-2026-10"):
    import hashlib
    expires = created + 300 if expires is None else expires
    comps = ['"@method"', '"@authority"', '"@path"', '"@query"']
    headers = {"host": host, "x-assay-call-id": call_id}
    path, _, q = target.partition("?")
    lines = [f'"@method": {method}', f'"@authority": {host}', f'"@path": {path or "/"}', f'"@query": ?{q}']
    if body is not None:
        d = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
        headers["content-digest"] = d
        comps.append('"content-digest"')
        lines.append(f'"content-digest": {d}')
    comps.append('"x-assay-call-id"')
    lines.append(f'"x-assay-call-id": {call_id}')
    params = f'({" ".join(comps)});created={created};expires={expires};nonce="{nonce}";keyid="{kid}";alg="ed25519";tag="assay-request"'
    lines.append(f'"@signature-params": {params}')
    sig = KEY.sign("\n".join(lines).encode())
    headers["signature-input"] = "assay=" + params
    headers["signature"] = "assay=:" + base64.b64encode(sig).decode() + ":"
    return method, target, headers, body


def make(**kw):
    kw.setdefault("jwks", {"keys": [JWK]})
    kw.setdefault("now", lambda: 1000)
    kw.setdefault("replay_store", MemoryReplayStore())
    return Verifier(**kw)


def test_sanity_roundtrip():
    assert make().verify(*sign()).ok


def test_expires_before_created():
    assert make().verify(*sign(created=1000, expires=990)).reason == RejectReason.EXPIRED


def test_validity_over_300():
    assert make().verify(*sign(created=1000, expires=1301)).reason == RejectReason.EXPIRED


def test_double_slash_target_malformed():
    assert make().verify(*sign(target="//evil.test/p")).reason == RejectReason.MALFORMED


def test_relative_without_slash_malformed():
    assert make().verify(*sign(target="p")).reason == RejectReason.MALFORMED


def test_authority_option_overrides_host():
    m, t, h, b = sign(host="api.example.test")
    h["host"] = "internal:8080"
    assert make(authority="API.example.test").verify(m, t, h, b).ok
    assert make().verify(m, t, h, b).reason == RejectReason.BAD_SIGNATURE


def test_authority_from_absolute_url_without_host():
    m, t, h, b = sign()
    del h["host"]
    assert make().verify(m, "https://API.example.test:443" + t, h, b).ok


def test_no_authority_malformed():
    m, t, h, b = sign()
    del h["host"]
    assert make().verify(m, t, h, b).reason == RejectReason.MALFORMED


def test_empty_body_present_requires_digest():
    # body b"" present and signed with digest
    assert make().verify(*sign(method="POST", body=b"")).ok
    m, t, h, _ = sign(method="POST", body=None, nonce="n2")
    assert make().verify(m, t, h, b"x").reason == RejectReason.MALFORMED


def test_replay_shared_default_store(monkeypatch):
    from goassay_provider_verify import core
    monkeypatch.setattr(core, "_DEFAULT_REPLAY", MemoryReplayStore())
    req = sign(nonce="shared")
    a = Verifier(jwks={"keys": [JWK]}, now=lambda: 1000)
    b = Verifier(jwks={"keys": [JWK]}, now=lambda: 1000)
    assert a.verify(*req).ok
    assert b.verify(*req).reason == RejectReason.REPLAYED


def test_garbage_headers():
    m, t, h, b = sign()
    h["signature"] = "assay=:!!!:"
    assert make().verify(m, t, h, b).reason == RejectReason.MALFORMED
    m, t, h, b = sign(nonce="n3")
    h["signature-input"] = "assay=("
    assert make().verify(m, t, h, b).reason == RejectReason.MALFORMED


def test_header_lookup_case_insensitive():
    m, t, h, b = sign()
    h = {k.title(): v for k, v in h.items()}
    assert make().verify(m, t, h, b).ok


# ---- JWKS ----

class FakeResp:
    def __init__(self, payload, status=200):
        self.payload, self.status = payload, status

    def read(self, *a):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture(autouse=True)
def clear_caches():
    jwks_mod._CACHES.clear()
    yield
    jwks_mod._CACHES.clear()


def test_jwks_fetch_timeout_backoff_and_recovery(monkeypatch):
    calls = []
    state = {"fail": True}

    def fake_open(req, timeout=None):
        calls.append(timeout)
        if state["fail"]:
            raise urllib.error.URLError("down")
        return FakeResp({"keys": [JWK]})

    monkeypatch.setattr(jwks_mod, "urlopen", fake_open)
    clock = {"t": 1000}
    v = Verifier(jwks_url="https://x.test/k.json", now=lambda: clock["t"], replay_store=MemoryReplayStore())
    assert v.verify(*sign(nonce="a")).reason == RejectReason.UNKNOWN_KEY
    assert calls == [5]
    clock["t"] = 1003  # inside the 5 s backoff
    assert v.verify(*sign(created=1003, nonce="b")).reason == RejectReason.UNKNOWN_KEY
    assert len(calls) == 1
    state["fail"] = False
    clock["t"] = 1006
    assert v.verify(*sign(created=1006, nonce="c")).ok
    assert len(calls) == 2


def test_jwks_unknown_kid_refetch_at_most_once_per_60s(monkeypatch):
    calls = []

    def fake_open(req, timeout=None):
        calls.append(1)
        return FakeResp({"keys": [JWK]})

    monkeypatch.setattr(jwks_mod, "urlopen", fake_open)
    clock = {"t": 1000}
    v = Verifier(jwks_url="https://y.test/k.json", now=lambda: clock["t"], replay_store=MemoryReplayStore())
    assert v.verify(*sign(nonce="a")).ok
    for i, t in enumerate((1001, 1030)):
        clock["t"] = t
        assert v.verify(*sign(created=t, nonce=f"u{i}", kid="other")).reason == RejectReason.UNKNOWN_KEY
    assert len(calls) == 1
    clock["t"] = 1061
    assert v.verify(*sign(created=1061, nonce="u9", kid="other")).reason == RejectReason.UNKNOWN_KEY
    assert len(calls) == 2


def test_jwks_cache_shared_per_url(monkeypatch):
    calls = []

    def fake_open(req, timeout=None):
        calls.append(1)
        return FakeResp({"keys": [JWK]})

    monkeypatch.setattr(jwks_mod, "urlopen", fake_open)
    r = MemoryReplayStore()
    a = Verifier(jwks_url="https://z.test/k.json", now=lambda: 1000, replay_store=r)
    b = Verifier(jwks_url="https://z.test/k.json", now=lambda: 1000, replay_store=r)
    assert a.verify(*sign(nonce="a")).ok
    assert b.verify(*sign(nonce="b")).ok
    assert len(calls) == 1


def test_environment_urls():
    assert jwks_mod.resolve_jwks_url(None, "production") == "https://api.goassay.ai/.well-known/assay-request-keys.json"
    assert jwks_mod.resolve_jwks_url(None, "testnet") == "https://api-dev.goassay.ai/.well-known/assay-request-keys.json"
    assert jwks_mod.resolve_jwks_url("https://a/b", "testnet") == "https://a/b"


# ---- replay ----

def test_memory_store_lru_eviction():
    s = MemoryReplayStore(max_entries=2)
    assert s.check_and_store("a", 60) and s.check_and_store("b", 60) and s.check_and_store("c", 60)
    assert s.check_and_store("a", 60)  # evicted earlier, accepted again
    assert not s.check_and_store("c", 60)


class FakeRedis:
    def __init__(self):
        self.data = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = (value, ex)
        return True


def test_redis_store_second_use_false():
    c = FakeRedis()
    s = redis_replay_store(c)
    assert s.check_and_store("n", 12.2) is True
    assert s.check_and_store("n", 12.2) is False
    assert "assay:nonce:n" in c.data and c.data["assay:nonce:n"][1] == 13


def test_asgi_slow_jwks_fetch_does_not_block_event_loop(monkeypatch):
    import asyncio
    import threading

    from goassay_provider_verify.asgi import AssayVerifyMiddleware

    released = threading.Event()
    seen = {}

    def slow_open(req, timeout=None):
        # Blocks until the event loop sets the event; if verification ran on the loop, it never could.
        seen["unblocked"] = released.wait(timeout=3)
        return FakeResp({"keys": [JWK]})

    monkeypatch.setattr(jwks_mod, "urlopen", slow_open)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = AssayVerifyMiddleware(app, jwks_url="https://slow.test/k.json", now=lambda: 1000,
                               replay_store=MemoryReplayStore())
    method, target, headers, _ = sign(nonce="slow")
    path, _, qs = target.partition("?")
    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(),
             "query_string": qs.encode(), "headers": [(k.encode(), v.encode()) for k, v in headers.items()]}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    async def other_request():
        await asyncio.sleep(0.05)  # runs only if the loop is free while the fetch is in flight
        released.set()

    async def main():
        await asyncio.gather(mw(scope, receive, send), other_request())

    asyncio.run(main())
    assert seen["unblocked"] is True
    assert sent[0]["status"] == 200
