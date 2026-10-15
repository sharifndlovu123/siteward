"""Safety layer: every outbound request in the project goes through here.

Known limit: DNS is resolved once for validation and again by the HTTP stack, so a
hostile resolver could in theory rebind between the two. Acceptable for v1 (documented).
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

USER_AGENT = "webscan/0.1 (passive security scanner)"
MAX_BODY = 2 * 1024 * 1024
MAX_REDIRECTS = 5
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class BlockedTarget(ValueError):
    """The target is not allowed to be scanned."""


class FetchError(Exception):
    """The target could not be fetched (network error, too many redirects, ...)."""


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    ips: tuple


def _is_public(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def validate_target(raw_url: str, allow_private: bool = False) -> Target:
    raw = (raw_url or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise BlockedTarget("invalid URL") from None
    if parts.scheme not in ("http", "https"):
        raise BlockedTarget("only http and https URLs are allowed")
    if parts.username or parts.password:
        raise BlockedTarget("URLs with credentials are not allowed")
    if not parts.hostname:
        raise BlockedTarget("URL has no host")

    host = parts.hostname.rstrip(".").lower()
    port = port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise BlockedTarget(f"cannot resolve host: {host}") from None
    ips = tuple(dict.fromkeys(info[4][0] for info in infos))
    if not ips:
        raise BlockedTarget(f"cannot resolve host: {host}")
    if not allow_private:
        private = [ip for ip in ips if not _is_public(ip)]
        if private:
            raise BlockedTarget("target resolves to a private or internal address")

    default_port = 443 if parts.scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host
    netloc = shown if port == default_port else f"{shown}:{port}"
    url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
    return Target(url, parts.scheme, host, port, ips)


@dataclass
class Fetch:
    url: str  # final URL after redirects
    status: int
    headers: httpx.Headers
    body: bytes
    chain: list

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class GuardedClient:
    def __init__(self, allow_private=False, min_interval=0.05, timeout=10.0, transport=None):
        self.allow_private = allow_private
        self._min_interval = min_interval
        self._lock = threading.Lock()
        self._last = 0.0
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            transport=transport,
        )

    def close(self):
        self._client.close()

    def _pace(self):
        with self._lock:
            wait = self._last + self._min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    @staticmethod
    def _read_capped(response) -> bytes:
        buf = bytearray()
        for chunk in response.iter_bytes():
            buf.extend(chunk)
            if len(buf) >= MAX_BODY:
                del buf[MAX_BODY:]
                break
        return bytes(buf)

    def get(self, url: str, follow: bool = True, headers: dict | None = None) -> Fetch:
        chain = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            validate_target(current, self.allow_private)  # re-validated on every hop
            chain.append(current)
            self._pace()
            try:
                with self._client.stream("GET", current, headers=headers) as response:
                    body = self._read_capped(response)
                    status, response_headers = response.status_code, response.headers
            except httpx.HTTPError as exc:
                raise FetchError(f"{type(exc).__name__}: {exc}") from exc
            location = response_headers.get("location")
            if follow and status in _REDIRECT_STATUSES and location:
                current = urljoin(current, location)
                continue
            return Fetch(current, status, response_headers, body, chain)
        raise FetchError("too many redirects")
