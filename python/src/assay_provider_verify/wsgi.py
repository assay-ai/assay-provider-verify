from __future__ import annotations

import io
from typing import Any, Dict, Iterable, Optional
from urllib.parse import quote

from .core import Verifier, rejection_body

DEFAULT_MAX_BODY_BYTES = 5_242_880
PAYLOAD_TOO_LARGE = '{"error":"payload_too_large"}'
PATH_SAFE = "/:@!$&'()*+,;=-._~"


def _headers_from_environ(environ: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            headers[k[5:].replace("_", "-").lower()] = v
    if environ.get("CONTENT_TYPE"):
        headers["content-type"] = environ["CONTENT_TYPE"]
    if environ.get("CONTENT_LENGTH") not in (None, ""):
        headers["content-length"] = environ["CONTENT_LENGTH"]
    return headers


def _target(environ: Dict[str, Any]) -> str:
    uri = environ.get("REQUEST_URI") or environ.get("RAW_URI")
    if uri:
        return uri
    path = quote((environ.get("SCRIPT_NAME") or "") + (environ.get("PATH_INFO") or ""), safe=PATH_SAFE, encoding="latin-1") or "/"
    qs = environ.get("QUERY_STRING") or ""
    return path + ("?" + qs if qs else "")


def _read(stream: Any, length: Optional[int], mx: int) -> Optional[bytes]:
    """Reads the body, or None when it exceeds mx. length None = until EOF."""
    chunks = []
    total = 0
    remaining = length
    while remaining is None or remaining > 0:
        n = 65536 if remaining is None else min(65536, remaining)
        chunk = stream.read(n)
        if not chunk:
            break
        total += len(chunk)
        if total > mx:
            return None
        chunks.append(chunk)
        if remaining is not None:
            remaining -= len(chunk)
    return b"".join(chunks)


class AssayVerifyWSGI:
    """WSGI middleware (Flask/Django): ``app.wsgi_app = AssayVerifyWSGI(app.wsgi_app)``."""

    def __init__(self, app: Any, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES, **verifier_kwargs: Any) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.verifier = Verifier(**verifier_kwargs)

    def _respond(self, start_response: Any, status: str, body: str) -> Iterable[bytes]:
        data = body.encode("utf-8")
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(data)))])
        return [data]

    def __call__(self, environ: Dict[str, Any], start_response: Any) -> Iterable[bytes]:
        mx = self.max_body_bytes
        cl = (environ.get("CONTENT_LENGTH") or "").strip()
        declared: Optional[int] = int(cl) if cl.isdigit() else None
        if declared is not None and declared > mx:
            return self._respond(start_response, "413 Payload Too Large", PAYLOAD_TOO_LARGE)

        chunked = bool(environ.get("HTTP_TRANSFER_ENCODING"))
        raw = b""
        # Without Content-Length, read to EOF only when the server marks the
        # input as terminated (PEP 3333 extension); otherwise reading could block.
        if declared is not None or (chunked and environ.get("wsgi.input_terminated")):
            raw = _read(environ["wsgi.input"], declared, mx)  # type: ignore[assignment]
            if raw is None:
                return self._respond(start_response, "413 Payload Too Large", PAYLOAD_TOO_LARGE)

        has_body = len(raw) > 0 or declared is not None or chunked
        headers = _headers_from_environ(environ)
        result = self.verifier.verify(environ.get("REQUEST_METHOD", "GET"), _target(environ), headers,
                                      raw if has_body else None)
        if not result.ok:
            return self._respond(start_response, "401 Unauthorized", rejection_body(result.reason))  # type: ignore[arg-type]

        environ["wsgi.input"] = io.BytesIO(raw)
        if has_body:
            environ["CONTENT_LENGTH"] = str(len(raw))
        return self.app(environ, start_response)
