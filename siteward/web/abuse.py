"""Minimal abuse log: who started a scan, never what was found."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _hmac(key: str, host: str) -> str:
    return hmac.new(key.encode(), host.strip().lower().encode(), hashlib.sha256).hexdigest()


class AbuseLog:
    def __init__(self, directory, key, retention_days=30, enabled=True, clock=time.time):
        self._dir = Path(directory)
        self._key = key
        self._retention = retention_days
        self._enabled = enabled
        self._clock = clock
        self._lock = threading.Lock()

    def target_hmac(self, host: str) -> str:
        return _hmac(self._key, host)

    def record(self, ip, host, options, outcome):
        if not self._enabled:
            return
        now = datetime.fromtimestamp(self._clock(), timezone.utc)
        line = json.dumps({"ts": now.isoformat(), "ip": ip, "target_hmac": self.target_hmac(host),
                           "options": options, "outcome": outcome}, separators=(",", ":"))
        try:
            with self._lock:
                self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                # Holds client IPs: owner-only, whatever the process umask is.
                fd = os.open(self._dir / f"abuse-{now:%Y-%m-%d}.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._prune(now)
        except OSError:
            logger.warning("abuse log is not writable")  # never log scan details

    def _prune(self, now):
        for path in self._dir.glob("abuse-*.log"):
            try:
                day = datetime.strptime(path.stem.removeprefix("abuse-"), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if (now - day).days > self._retention:
                path.unlink(missing_ok=True)


def lookup(directory, key, host) -> list:
    """Return log lines whose target matches the reported hostname (for answering abuse reports)."""
    wanted, hits = _hmac(key, host), []
    for path in sorted(Path(directory).glob("abuse-*.log")):
        for raw in path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            if entry.get("target_hmac") == wanted:
                hits.append(entry)
    return hits


if __name__ == "__main__":  # python -m siteward.web.abuse DIRECTORY HOSTNAME   (key from ABUSE_LOG_KEY)
    import os

    for hit in lookup(sys.argv[1], os.environ["ABUSE_LOG_KEY"], sys.argv[2]):
        print(json.dumps(hit))
