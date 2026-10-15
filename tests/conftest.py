import socket

import pytest

from tests.fake_server import FakeServer


@pytest.fixture
def server():
    s = FakeServer()
    s.start()
    yield s
    s.stop()


@pytest.fixture
def fake_dns(monkeypatch):
    """Map hostnames to IPs without touching real DNS. Unknown hosts fall through."""
    mapping = {}
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host in mapping:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return mapping


from webscan.core.context import build_context  # noqa: E402


@pytest.fixture
def ctx_for():
    def make(server, **options):
        opts = {"allow_private": True, "min_interval": 0}
        opts.update(options)
        return build_context(server.url, opts)

    return make
