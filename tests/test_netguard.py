import time

import httpx
import pytest

from siteward.core.netguard import (
    MAX_BODY,
    BlockedTarget,
    FetchError,
    GuardedClient,
    validate_target,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://10.0.0.5/",
        "http://192.168.1.1:8080/",
        "http://0.0.0.0/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "https://user:pw@example.com/",
        "",
    ],
)
def test_validate_rejects_unsafe_targets(url):
    with pytest.raises(BlockedTarget):
        validate_target(url)


def test_validate_rejects_unresolvable_host():
    with pytest.raises(BlockedTarget):
        validate_target("http://definitely-not-real.invalid/")


def test_validate_normalises_scheme_host_and_port(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    t = validate_target("Example.COM.")
    assert (t.scheme, t.host, t.port, t.url) == ("https", "example.com", 443, "https://example.com/")
    assert t.ips == ("93.184.216.34",)


def test_validate_allows_private_when_enabled():
    t = validate_target("127.0.0.1:8000", allow_private=True)
    assert t.url == "https://127.0.0.1:8000/" and t.port == 8000


def test_hostname_resolving_to_private_ip_is_blocked(fake_dns):
    fake_dns["evil.example"] = "10.1.2.3"
    with pytest.raises(BlockedTarget):
        validate_target("https://evil.example/")


def _client(handler):
    return GuardedClient(transport=httpx.MockTransport(handler), min_interval=0)


def test_redirect_to_metadata_address_is_blocked(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    with pytest.raises(BlockedTarget):
        _client(handler).get("https://example.com/")
    assert len(seen) == 1 and "169.254.169.254" not in seen[0]  # the internal address was never requested


def test_redirect_to_hostname_resolving_private_is_blocked(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    fake_dns["internal.example"] = "10.0.0.9"

    def handler(request):
        return httpx.Response(302, headers={"location": "https://internal.example/admin"})

    with pytest.raises(BlockedTarget):
        _client(handler).get("https://example.com/")


def test_safe_redirect_is_followed_and_chain_recorded(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "/final"})
        return httpx.Response(200, content=b"done")

    fetch = _client(handler).get("https://example.com/")
    assert fetch.status == 200 and fetch.url == "https://example.com/final"
    assert fetch.chain == ["https://example.com/", "https://example.com/final"]


def test_follow_false_returns_the_redirect_itself(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    handler = lambda request: httpx.Response(301, headers={"location": "https://example.com/x"})
    fetch = _client(handler).get("https://example.com/", follow=False)
    assert fetch.status == 301 and fetch.headers["location"] == "https://example.com/x"


def test_redirect_loop_raises_fetch_error(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    handler = lambda request: httpx.Response(302, headers={"location": "https://example.com/next"})
    with pytest.raises(FetchError):
        _client(handler).get("https://example.com/")


def test_oversized_body_is_capped(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    handler = lambda request: httpx.Response(200, content=b"x" * (MAX_BODY + 5000))
    assert len(_client(handler).get("https://example.com/").body) == MAX_BODY


def test_connection_failure_becomes_fetch_error(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"

    def handler(request):
        raise httpx.ConnectError("boom")

    with pytest.raises(FetchError):
        _client(handler).get("https://example.com/")


def test_requests_are_paced(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    client = GuardedClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)), min_interval=0.05)
    start = time.monotonic()
    for _ in range(3):
        client.get("https://example.com/")
    assert time.monotonic() - start >= 0.09


def test_real_local_request_needs_allow_private(server):
    assert GuardedClient(allow_private=True, min_interval=0).get(server.url + "/").status == 200
    with pytest.raises(BlockedTarget):
        GuardedClient(min_interval=0).get(server.url + "/")
