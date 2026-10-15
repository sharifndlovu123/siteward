from __future__ import annotations

from dataclasses import dataclass

from .netguard import Fetch, GuardedClient, Target, validate_target


@dataclass
class ScanContext:
    target: Target
    client: GuardedClient
    baseline: Fetch
    options: dict


def build_context(url: str, options: dict | None = None, client: GuardedClient | None = None) -> ScanContext:
    """Validate the target and fetch the baseline page once. May raise BlockedTarget or FetchError."""
    options = dict(options or {})
    allow_private = bool(options.get("allow_private"))
    target = validate_target(url, allow_private)
    client = client or GuardedClient(allow_private=allow_private, min_interval=options.get("min_interval", 0.05))
    baseline = client.get(target.url)
    return ScanContext(target, client, baseline, options)
