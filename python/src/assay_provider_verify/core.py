from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

from .jwks import JwksCache, resolve_jwks_url, shared_cache
from .replay import MemoryReplayStore, ReplayStore
from .structured import Bytes, Member, ParseError, parse_dictionary

__all__ = ["RejectReason", "VerifyResult", "Verifier", "rejection_body"]


class RejectReason(str, Enum):
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"
    WRONG_TAG = "WRONG_TAG"
    EXPIRED = "EXPIRED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    REPLAYED = "REPLAYED"


@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[RejectReason] = None
    key_id: Optional[str] = None
    call_id: Optional[str] = None


def rejection_body(reason: RejectReason) -> str:
    """JSON body for a 401 rejection; identical across adapters and languages."""
    return '{"error":"invalid_assay_signature","reason":"%s"}' % reason.value


_BASE_COMPONENTS = ["@method", "@authority", "@path", "@query"]
_MAX_VALIDITY_SECONDS = 300
_ABSOLUTE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# One process-wide default replay store, used when none is given.
_DEFAULT_REPLAY: ReplayStore = MemoryReplayStore()


def _reject(reason: RejectReason) -> VerifyResult:
    return VerifyResult(ok=False, reason=reason)


def _get_header(headers: Mapping[str, object], name: str) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() != name:
            continue
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            return ", ".join(str(x) for x in v)
        return v if isinstance(v, str) else str(v)
    return None


def _parse_target(url: str) -> Optional[Tuple[str, str, Optional[str]]]:
    """Returns (path, query, url_host). Absolute URLs use urlsplit (and supply a
    fallback authority); anything else is taken as sent, never resolved."""
    if url.startswith("//"):
        return None
    if _ABSOLUTE.match(url):
        try:
            u = urlsplit(url)
            host = u.hostname
            port = u.port
        except ValueError:
            return None
        if not host:
            return None
        if u.path.startswith("//"):
            return None
        authority = host.lower()
        if ":" in authority:
            authority = "[" + authority + "]"
        if port is not None and port != _DEFAULT_PORTS.get(u.scheme.lower()):
            authority += ":%d" % port
        return (u.path or "/", u.query, authority)
    if not url.startswith("/"):
        return None
    no_frag = url.split("#", 1)[0]
    q = no_frag.find("?")
    if q < 0:
        return (no_frag, "", None)
    return (no_frag[:q], no_frag[q + 1:], None)


def _int_param(m: Member, name: str) -> Optional[int]:
    v = m.params.get(name)
    return v if type(v) is int else None


def _str_param(m: Member, name: str) -> Optional[str]:
    v = m.params.get(name)
    return v if isinstance(v, str) and v else None


def _decode_b64(b64: str) -> bytes:
    b64 += "=" * (-len(b64) % 4)
    return base64.b64decode(b64, validate=True)


class Verifier:
    def __init__(
        self,
        jwks_url: Optional[str] = None,
        environment: str = "production",
        authority: Optional[str] = None,
        replay_store: Optional[ReplayStore] = None,
        clock_skew: int = 60,
        now: Optional[Callable[[], float]] = None,
        jwks: Optional[dict] = None,
    ) -> None:
        self._authority = authority
        self._skew = clock_skew
        self._now = now or _system_now
        self._replay = replay_store if replay_store is not None else _DEFAULT_REPLAY
        if jwks is not None:
            self._jwks = JwksCache(static=jwks)
        else:
            self._jwks = shared_cache(resolve_jwks_url(jwks_url, environment))

    def verify(self, method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> VerifyResult:
        # 1. Headers.
        sig_input_header = _get_header(headers, "signature-input")
        sig_header = _get_header(headers, "signature")
        if not sig_input_header or not sig_header:
            return _reject(RejectReason.MISSING)
        try:
            input_member = parse_dictionary(sig_input_header).get("assay")
            sig_member = parse_dictionary(sig_header).get("assay")
            if input_member is None or sig_member is None:
                return _reject(RejectReason.MISSING)
            if not isinstance(sig_member.item, Bytes):
                return _reject(RejectReason.MALFORMED)
            signature = _decode_b64(sig_member.item.b64)
        except (ParseError, binascii.Error, ValueError):
            return _reject(RejectReason.MALFORMED)

        # 2. Parameters.
        components = input_member.items
        if components is None:
            return _reject(RejectReason.MALFORMED)
        created = _int_param(input_member, "created")
        expires = _int_param(input_member, "expires")
        nonce = _str_param(input_member, "nonce")
        keyid = _str_param(input_member, "keyid")
        if input_member.params.get("tag") != "assay-request":
            return _reject(RejectReason.WRONG_TAG)
        if input_member.params.get("alg") != "ed25519" or created is None or expires is None or not nonce or not keyid:
            return _reject(RejectReason.MALFORMED)

        # 3. Components and digest.
        with_digest = "content-digest" in components
        expected: List[str] = list(_BASE_COMPONENTS)
        if with_digest:
            expected.append("content-digest")
        expected.append("x-assay-call-id")
        if components != expected:
            return _reject(RejectReason.MALFORMED)
        raw_body = body or b""
        if not with_digest and len(raw_body) > 0:
            return _reject(RejectReason.MALFORMED)
        digest_value: Optional[str] = None
        if with_digest:
            dv = _get_header(headers, "content-digest")
            digest_value = dv.strip() if dv else None
            if not digest_value:
                return _reject(RejectReason.MISSING)
            try:
                m = parse_dictionary(digest_value).get("sha-256")
            except ParseError:
                return _reject(RejectReason.MALFORMED)
            actual = base64.b64encode(hashlib.sha256(raw_body).digest()).decode("ascii")
            if m is None or not isinstance(m.item, Bytes) or m.item.b64 != actual:
                return _reject(RejectReason.DIGEST_MISMATCH)

        # 4. Time window.
        t = self._now()
        skew = self._skew
        if expires < created or expires - created > _MAX_VALIDITY_SECONDS or t < created - skew or t > expires + skew:
            return _reject(RejectReason.EXPIRED)

        # 5. Signature base.
        call_id_raw = _get_header(headers, "x-assay-call-id")
        call_id = call_id_raw.strip() if call_id_raw else None
        if not call_id:
            return _reject(RejectReason.MALFORMED)
        target = _parse_target(url)
        if target is None:
            return _reject(RejectReason.MALFORMED)
        path, query, url_host = target
        authority = self._resolve_authority(headers, url_host)
        if not authority:
            return _reject(RejectReason.MALFORMED)
        lines = [
            "\"@method\": " + method.upper(),
            "\"@authority\": " + authority,
            "\"@path\": " + (path or "/"),
            "\"@query\": ?" + query,
        ]
        if digest_value is not None:
            lines.append("\"content-digest\": " + digest_value)
        lines.append("\"x-assay-call-id\": " + call_id)
        lines.append("\"@signature-params\": " + input_member.raw)
        base = "\n".join(lines).encode("utf-8")

        # 6. Key lookup and signature.
        key = self._jwks.get_key(keyid, t)
        if key is None:
            return _reject(RejectReason.UNKNOWN_KEY)
        try:
            key.verify(signature, base)
        except (InvalidSignature, ValueError):
            return _reject(RejectReason.BAD_SIGNATURE)

        # 7. Replay.
        ttl = max(1, expires + skew - t)
        if not self._replay.check_and_store(nonce, ttl):
            return _reject(RejectReason.REPLAYED)

        return VerifyResult(ok=True, key_id=keyid, call_id=call_id)

    def _resolve_authority(self, headers: Mapping[str, str], url_host: Optional[str]) -> Optional[str]:
        if self._authority:
            return self._authority.lower()
        host = _get_header(headers, "host")
        if host and host.strip():
            return host.strip().lower()
        return url_host


def _system_now() -> float:
    import time

    return float(int(time.time()))
