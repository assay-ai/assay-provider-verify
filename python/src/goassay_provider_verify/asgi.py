from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Dict, List, TypeVar
from urllib.parse import quote

from .core import Verifier, rejection_body

try:  # Starlette/FastAPI depend on anyio; use it when present (works under asyncio and trio).
    from anyio import to_thread as _anyio_to_thread
except ImportError:  # pragma: no cover - exercised only without anyio installed
    _anyio_to_thread = None  # type: ignore[assignment]

T = TypeVar("T")


async def _run_in_thread(fn: Callable[..., T], *args: Any) -> T:
    """Run blocking work (JWKS fetch over urllib, sync Redis calls) off the event loop."""
    if _anyio_to_thread is not None:
        return await _anyio_to_thread.run_sync(functools.partial(fn, *args))
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(fn, *args))

DEFAULT_MAX_BODY_BYTES = 5_242_880
PAYLOAD_TOO_LARGE = '{"error":"payload_too_large"}'
PATH_SAFE = "/:@!$&'()*+,;=-._~"


async def _send_json(send: Any, status: int, body: str, close: bool = False) -> None:
    data = body.encode("utf-8")
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    if close:
        headers.append((b"connection", b"close"))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})


class AssayVerifyMiddleware:
    """ASGI middleware (FastAPI/Starlette): ``app.add_middleware(AssayVerifyMiddleware)``.

    Keyword arguments are the ``Verifier`` options plus ``max_body_bytes``.
    Verification is synchronous (a JWKS fetch can take up to 5 s; a Redis replay store
    uses a sync client), so it runs in a worker thread and never blocks the event loop.
    """

    def __init__(self, app: Any, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES, **verifier_kwargs: Any) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.verifier = Verifier(**verifier_kwargs)

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers: Dict[str, str] = {}
        for k, v in scope.get("headers", []):
            name = k.decode("latin-1").lower()
            val = v.decode("latin-1")
            headers[name] = headers[name] + ", " + val if name in headers else val

        mx = self.max_body_bytes
        declared = headers.get("content-length")
        if declared is not None and declared.strip().isdigit() and int(declared) > mx:
            await _send_json(send, 413, PAYLOAD_TOO_LARGE, close=True)
            return

        chunks: List[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > mx:
                await _send_json(send, 413, PAYLOAD_TOO_LARGE, close=True)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        raw = b"".join(chunks)

        has_body = len(raw) > 0 or "content-length" in headers or "transfer-encoding" in headers
        raw_path = scope.get("raw_path")
        path = raw_path.decode("latin-1") if raw_path else quote(scope.get("path", "/"), safe=PATH_SAFE)
        qs = scope.get("query_string", b"")
        url = path + ("?" + qs.decode("latin-1") if qs else "")

        result = await _run_in_thread(
            self.verifier.verify, scope.get("method", "GET"), url, headers, raw if has_body else None
        )
        if not result.ok:
            await _send_json(send, 401, rejection_body(result.reason))  # type: ignore[arg-type]
            return

        sent = False

        async def replay_receive() -> Dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
