"""In-memory result store. Nothing here ever touches disk."""
from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone

from siteward import __version__
from siteward.core.models import ScanReport

_STUCK_AFTER = 3600


class StoreFull(Exception):
    """Every slot holds an unfinished scan; refuse rather than evict someone else's in-flight result."""


class Entry:
    def __init__(self, scan_id, url, options, clock=time.time):
        self.id = scan_id
        self.url = url
        self.options = options
        self.status = "queued"  # queued | running | done | error
        self.results = []
        self.report = None
        self.error = ""
        self.created = clock()
        self.finished = None
        self.started = datetime.now(timezone.utc)

    def partial_report(self) -> ScanReport:
        return ScanReport(
            self.url, self.started, datetime.now(timezone.utc), __version__,
            {"ports": bool(self.options.get("ports"))}, list(self.results),
        )


class Store:
    def __init__(self, ttl=900, max_entries=20, clock=time.time):
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries = {}

    def _sweep(self):
        now = self._clock()
        for key, e in list(self._entries.items()):
            expired = (e.finished is not None and now - e.finished > self._ttl) or now - e.created > _STUCK_AFTER
            if expired:
                del self._entries[key]

    def create(self, url, options) -> Entry:
        with self._lock:
            self._sweep()
            while len(self._entries) >= self._max:
                finished = [e for e in self._entries.values() if e.finished is not None]
                if not finished:
                    raise StoreFull
                del self._entries[min(finished, key=lambda e: e.created).id]
            entry = Entry(secrets.token_urlsafe(16), url, options, clock=self._clock)
            self._entries[entry.id] = entry
            return entry

    def get(self, scan_id):
        with self._lock:
            self._sweep()
            return self._entries.get(scan_id)
