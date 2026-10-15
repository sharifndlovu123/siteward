"""In-memory rate limiting. Keys are HMAC'd so raw IPs/hostnames are not held in memory tables."""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque


class SlidingWindow:
    def __init__(self, limit, window, key: bytes, clock=time.monotonic):
        self._limit, self._window, self._key, self._clock = limit, window, key, clock
        self._lock = threading.Lock()
        self._hits = {}
        self._last_sweep = clock()

    def _hash(self, raw: str) -> str:
        return hmac.new(self._key, raw.encode(), hashlib.sha256).hexdigest()

    def allow(self, raw_key: str) -> bool:
        key, now = self._hash(raw_key), self._clock()
        with self._lock:
            if now - self._last_sweep > 60:
                self._last_sweep = now
                for k in [k for k, q in self._hits.items() if not q or now - q[-1] > self._window]:
                    del self._hits[k]
            queue = self._hits.setdefault(key, deque())
            while queue and now - queue[0] > self._window:
                queue.popleft()
            if len(queue) >= self._limit:
                return False
            queue.append(now)
            return True


class Slots:
    """Bounds concurrent scans plus a small waiting queue."""

    def __init__(self, concurrent, queue):
        self.sem = threading.Semaphore(concurrent)
        self._cap = concurrent + queue
        self._n = 0
        self._lock = threading.Lock()

    def reserve(self) -> bool:
        with self._lock:
            if self._n >= self._cap:
                return False
            self._n += 1
            return True

    def release(self):
        with self._lock:
            self._n -= 1
