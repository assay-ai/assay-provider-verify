from __future__ import annotations

import base64
import json
import threading
import urllib.request
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

JWKS_URL_PRODUCTION = "https://api.goassay.ai/.well-known/assay-request-keys.json"
JWKS_URL_TESTNET = "https://api-dev.goassay.ai/.well-known/assay-request-keys.json"

CACHE_TTL_SECONDS = 3600
REFETCH_MIN_INTERVAL_SECONDS = 60
FETCH_TIMEOUT_SECONDS = 5
FAILURE_BACKOFF_SECONDS = 5
_MAX_JWKS_BYTES = 1_048_576

urlopen = urllib.request.urlopen  # indirection point for tests


def resolve_jwks_url(jwks_url: Optional[str], environment: str = "production") -> str:
    if jwks_url:
        return jwks_url
    return JWKS_URL_TESTNET if environment == "testnet" else JWKS_URL_PRODUCTION


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load(raw: Any) -> Dict[str, Ed25519PublicKey]:
    keys: Dict[str, Ed25519PublicKey] = {}
    for jwk in raw:
        if not isinstance(jwk, dict):
            continue
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        x, kid = jwk.get("x"), jwk.get("kid")
        if not isinstance(x, str) or not isinstance(kid, str):
            continue
        try:
            keys[kid] = Ed25519PublicKey.from_public_bytes(_b64url_decode(x))
        except Exception:
            continue  # skip unusable key
    return keys


class JwksCache:
    """Ed25519 public keys by kid. The clock (unix seconds) is passed per call."""

    def __init__(self, url: Optional[str] = None, static: Optional[dict] = None) -> None:
        self.url = url
        self._static = static
        self._keys: Dict[str, Ed25519PublicKey] = _load(static["keys"]) if static is not None else {}
        self._loaded_at: Optional[float] = None
        self._failed_at: Optional[float] = None
        self._lock = threading.Lock()

    def get_key(self, kid: str, now: float) -> Optional[Ed25519PublicKey]:
        if self._static is not None:
            return self._keys.get(kid)
        # The lock is held across a fetch so no request sees "unknown kid" mid-load.
        with self._lock:
            fresh = self._loaded_at is not None and now - self._loaded_at < CACHE_TTL_SECONDS
            if fresh:
                hit = self._keys.get(kid)
                if hit is not None:
                    return hit
                if now - self._loaded_at < REFETCH_MIN_INTERVAL_SECONDS:  # type: ignore[operator]
                    return None
            if self._failed_at is not None and now - self._failed_at < FAILURE_BACKOFF_SECONDS:
                return self._keys.get(kid)
            self._fetch(now)
            return self._keys.get(kid)

    def _fetch(self, now: float) -> None:
        try:
            req = urllib.request.Request(self.url, headers={"accept": "application/json"})  # type: ignore[arg-type]
            with urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as res:
                status = getattr(res, "status", 200)
                if status != 200:
                    raise ValueError("jwks http %s" % status)
                body = json.loads(res.read(_MAX_JWKS_BYTES))
            if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
                raise ValueError("jwks shape")
            self._keys = _load(body["keys"])
            self._loaded_at = now
            self._failed_at = None
        except Exception:
            self._failed_at = now


_CACHES: Dict[str, JwksCache] = {}
_CACHES_LOCK = threading.Lock()


def shared_cache(url: str) -> JwksCache:
    """JWKS caches are shared per resolved URL, process-wide."""
    with _CACHES_LOCK:
        c = _CACHES.get(url)
        if c is None:
            c = _CACHES[url] = JwksCache(url=url)
        return c
