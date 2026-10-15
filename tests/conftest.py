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


from datetime import datetime, timezone  # noqa: E402

from webscan.core.models import CheckResult, Finding, ScanReport  # noqa: E402

HOSTILE = "<script>alert(1)</script>"


@pytest.fixture
def sample_report():
    now = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    results = [
        CheckResult("headers.security", "Headers", "findings",
                    [Finding("headers.csp", "CSP missing", "Headers", "medium", "header not present", "Add a CSP")]),
        CheckResult("leakage.banner", "Leakage", "findings",
                    [Finding("leakage.x-powered-by", f"X-Powered-By: {HOSTILE}", "Leakage", "low",
                             f"x-powered-by: {HOSTILE}\n```evil```", "Remove it")]),
        CheckResult("tls.certificate", "TLS", "skipped", message="target is not served over HTTPS"),
        CheckResult("cookies.flags", "Cookies", "passed"),
        CheckResult("dns.email", "DNS", "error", message="TimeoutError: lookup"),
    ]
    return ScanReport("http://example.com/", now, now, "0.1.0", {"ports": False}, results)
