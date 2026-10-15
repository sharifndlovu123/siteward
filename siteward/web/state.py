"""Process-wide singletons, built lazily from settings (tests call reset())."""
import os
import threading
from dataclasses import dataclass

from django.conf import settings

from siteward.core.runner import discover_checks

from .abuse import AbuseLog
from .limits import SlidingWindow, Slots
from .store import Store

_lock = threading.Lock()
_state = None


@dataclass
class State:
    store: Store
    ip_limiter: SlidingWindow
    target_limiter: SlidingWindow
    slots: Slots
    abuse: AbuseLog
    total_checks: int


def get() -> State:
    global _state
    with _lock:
        if _state is None:
            key = os.urandom(32)
            _state = State(
                store=Store(settings.SCAN_TTL_SECONDS, settings.MAX_STORED_SCANS),
                ip_limiter=SlidingWindow(settings.RATE_PER_IP, settings.RATE_WINDOW, key),
                target_limiter=SlidingWindow(settings.RATE_PER_TARGET, settings.RATE_WINDOW, key),
                slots=Slots(settings.MAX_CONCURRENT_SCANS, settings.MAX_QUEUE),
                abuse=AbuseLog(settings.ABUSE_LOG_DIR, settings.ABUSE_LOG_KEY, settings.ABUSE_LOG_RETENTION_DAYS,
                               enabled=settings.ABUSE_LOG),
                total_checks=len(discover_checks()),
            )
        return _state


def reset():
    global _state
    with _lock:
        _state = None
