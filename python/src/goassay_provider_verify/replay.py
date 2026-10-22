from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from typing import Any, Optional


class ReplayStore:
    """Interface: ``check_and_store`` returns True when the nonce was not seen
    before (and is now stored for ``ttl_seconds``), False for a replay."""

    def check_and_store(self, nonce: str, ttl_seconds: float) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class MemoryReplayStore(ReplayStore):
    """In-memory LRU replay store (oldest entries evicted first)."""

    def __init__(self, max_entries: int = 100_000) -> None:
        self._max = max_entries
        self._entries: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def check_and_store(self, nonce: str, ttl_seconds: float) -> bool:
        now = time.time()
        with self._lock:
            existing: Optional[float] = self._entries.get(nonce)
            if existing is not None:
                if existing > now:
                    return False
                del self._entries[nonce]
            self._entries[nonce] = now + max(0.0, ttl_seconds)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
            return True


class _RedisStore(ReplayStore):
    def __init__(self, client: Any, prefix: str) -> None:
        self._client = client
        self._prefix = prefix

    def check_and_store(self, nonce: str, ttl_seconds: float) -> bool:
        ex = max(1, math.ceil(ttl_seconds))
        # Redis errors propagate: verification fails closed.
        return bool(self._client.set(self._prefix + nonce, "1", nx=True, ex=ex))


def redis_replay_store(client: Any, prefix: str = "assay:nonce:") -> ReplayStore:
    """Replay store backed by Redis (SET NX EX) for redis-py compatible clients."""
    if client is None or not callable(getattr(client, "set", None)):
        raise TypeError("redis_replay_store: client must expose set()")
    return _RedisStore(client, prefix)
