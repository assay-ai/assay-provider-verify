import json
from pathlib import Path

import pytest

from goassay_provider_verify import MemoryReplayStore, RejectReason, Verifier

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors"
V1 = json.loads((VECTORS / "v1.json").read_text())
NEG = json.loads((VECTORS / "negative.json").read_text())


def to_args(r, extra=None):
    headers = dict(r["headers"])
    headers.update(extra or {})
    body = r.get("body")
    return r["method"], r["url"], headers, None if body is None else body.encode("utf-8")


@pytest.mark.parametrize("case", V1["cases"], ids=lambda c: c["name"])
def test_positive(case):
    aud = case["params"]["audience"]
    v = Verifier(provider=aud, jwks={"keys": [V1["publicKeyJwk"]]}, now=lambda: case["params"]["created"],
                 replay_store=MemoryReplayStore())
    res = v.verify(*to_args(case["request"], case["expected"]["headers"]))
    assert res.ok, res.reason
    assert res.key_id == V1["keyId"]
    assert res.call_id == "c-1"
    assert res.provider_id == aud


@pytest.mark.parametrize("case", V1["cases"], ids=lambda c: c["name"])
def test_positive_provider_list(case):
    aud = case["params"]["audience"]
    v = Verifier(provider=["prov-other", aud], jwks={"keys": [V1["publicKeyJwk"]]},
                 now=lambda: case["params"]["created"], replay_store=MemoryReplayStore())
    res = v.verify(*to_args(case["request"], case["expected"]["headers"]))
    assert res.ok, res.reason
    assert res.provider_id == aud


@pytest.mark.parametrize("case", V1["cases"], ids=lambda c: c["name"])
def test_positive_other_provider(case):
    v = Verifier(provider=("prov-other", "prov-test-2"), jwks={"keys": [V1["publicKeyJwk"]]},
                 now=lambda: case["params"]["created"], replay_store=MemoryReplayStore())
    res = v.verify(*to_args(case["request"], case["expected"]["headers"]))
    assert not res.ok
    assert res.reason == RejectReason.WRONG_PROVIDER
    assert res.provider_id is None


def test_provider_required():
    with pytest.raises(TypeError, match="provider"):
        Verifier(jwks={"keys": [V1["publicKeyJwk"]]})


@pytest.mark.parametrize("bad", ["", [], [""], ["ok", 1], "has space", "a,b", "x" * 129, "ok\n"])
def test_provider_invalid(bad):
    with pytest.raises(ValueError):
        Verifier(provider=bad, jwks={"keys": [V1["publicKeyJwk"]]})


@pytest.mark.parametrize("case", NEG["cases"], ids=lambda c: c["name"])
def test_negative(case):
    steps = case.get("sequence") or [{"request": case["request"], "now": case["now"], "expectedReason": case["expectedReason"]}]
    clock = {"now": 0}
    v = Verifier(provider=NEG["provider"], jwks={"keys": [NEG["publicKeyJwk"]]}, now=lambda: clock["now"],
                 replay_store=MemoryReplayStore())
    for s in steps:
        clock["now"] = s["now"]
        res = v.verify(*to_args(s["request"]))
        if s["expectedReason"] == "OK":
            assert res.ok, res.reason
        else:
            assert not res.ok
            assert res.reason == RejectReason(s["expectedReason"])
            assert res.key_id is None
