import json
from pathlib import Path

import pytest

from assay_provider_verify import AssayVerifyMiddleware, AssayVerifyWSGI, MemoryReplayStore

V1 = json.loads((Path(__file__).resolve().parents[2] / "test-vectors" / "v1.json").read_text())
CASE = next(c for c in V1["cases"] if c["name"] == "post-json-body")
SIGNED = {**CASE["request"]["headers"], **CASE["expected"]["headers"], "content-type": "application/json"}
BODY = CASE["request"]["body"]
PATH = "/v1/search?q=a%20b"


def opts(**kw):
    return dict(jwks={"keys": [V1["publicKeyJwk"]]}, now=lambda: CASE["params"]["created"],
                replay_store=MemoryReplayStore(), authority="api.example.test", **kw)


def fastapi_client(**kw):
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.post("/v1/search")
    async def search(request: Request):
        return {"echo": await request.json(), "q": request.query_params["q"]}

    app.add_middleware(AssayVerifyMiddleware, **opts(**kw))
    return TestClient(app)


def flask_client(**kw):
    from flask import Flask, request

    app = Flask(__name__)

    @app.post("/v1/search")
    def search():
        return {"echo": request.get_json(), "q": request.args["q"]}

    app.wsgi_app = AssayVerifyWSGI(app.wsgi_app, **opts(**kw))
    return app.test_client()


REJECT = {"error": "invalid_assay_signature"}


def test_fastapi_valid():
    r = fastapi_client().post(PATH, content=BODY, headers=SIGNED)
    assert r.status_code == 200, r.text
    assert r.json() == {"echo": {"q": "a b"}, "q": "a b"}


def test_fastapi_tampered():
    r = fastapi_client().post(PATH, content='{"q":"evil"}', headers=SIGNED)
    assert r.status_code == 401
    assert r.headers["content-type"] == "application/json"
    assert r.text == '{"error":"invalid_assay_signature","reason":"DIGEST_MISMATCH"}'


def test_fastapi_replay():
    c = fastapi_client()
    assert c.post(PATH, content=BODY, headers=SIGNED).status_code == 200
    r = c.post(PATH, content=BODY, headers=SIGNED)
    assert r.status_code == 401 and r.json()["reason"] == "REPLAYED"


def test_fastapi_missing_headers():
    r = fastapi_client().post(PATH, content=BODY)
    assert r.status_code == 401 and r.json()["reason"] == "MISSING"


def test_fastapi_413():
    r = fastapi_client(max_body_bytes=4).post(PATH, content=BODY, headers=SIGNED)
    assert r.status_code == 413 and r.text == '{"error":"payload_too_large"}'


def test_fastapi_non_http_scope_passthrough():
    import asyncio

    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    mw = AssayVerifyMiddleware(app, **opts())
    asyncio.run(mw({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


def test_flask_valid():
    r = flask_client().post(PATH, data=BODY, headers=SIGNED)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == {"echo": {"q": "a b"}, "q": "a b"}


def test_flask_tampered():
    r = flask_client().post(PATH, data='{"q":"evil"}', headers=SIGNED)
    assert r.status_code == 401
    assert r.headers["content-type"] == "application/json"
    assert r.get_data(as_text=True) == '{"error":"invalid_assay_signature","reason":"DIGEST_MISMATCH"}'


def test_flask_replay_and_413():
    c = flask_client()
    assert c.post(PATH, data=BODY, headers=SIGNED).status_code == 200
    assert c.post(PATH, data=BODY, headers=SIGNED).get_json()["reason"] == "REPLAYED"
    r = flask_client(max_body_bytes=4).post(PATH, data=BODY, headers=SIGNED)
    assert r.status_code == 413 and r.get_data(as_text=True) == '{"error":"payload_too_large"}'


def test_wsgi_chunked_without_length_and_non_uploaded_get():
    # GET without body: no digest component, handler still runs.
    import io

    v = V1["cases"]
    case = next(c for c in v if c["name"] == "get-with-query")
    seen = {}

    def app(environ, start_response):
        seen["len"] = environ.get("CONTENT_LENGTH")
        start_response("200 OK", [("content-type", "text/plain")])
        return [b"ok"]

    mw = AssayVerifyWSGI(app, jwks={"keys": [V1["publicKeyJwk"]]}, now=lambda: case["params"]["created"],
                         replay_store=MemoryReplayStore())
    h = {**case["request"]["headers"], **case["expected"]["headers"], "host": "api.example.test"}
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/items", "QUERY_STRING": "id=1&x=%2F",
               "wsgi.input": io.BytesIO(b""), "SERVER_NAME": "x", "SERVER_PORT": "80"}
    for k, val in h.items():
        environ["HTTP_" + k.upper().replace("-", "_")] = val
    out = {}
    res = mw(environ, lambda s, hd, exc=None: out.update(status=s), )
    assert out["status"].startswith("200"), b"".join(res)
