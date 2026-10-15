from types import SimpleNamespace as NS

import httpx

from webscan.checks import redirect_https
from webscan.core.netguard import Fetch, FetchError


def test_plain_http_without_redirect_is_flagged(server, ctx_for):
    found = redirect_https.run(ctx_for(server))
    assert [f.id for f in found] == ["transport.no-https-redirect"]


def test_redirect_to_https_passes():
    class Client:
        def get(self, url, follow=True, headers=None):
            return Fetch(url, 301, httpx.Headers({"location": "https://example.com/"}), b"", [url])

    ctx = NS(target=NS(scheme="https", host="example.com", url="https://example.com/"), client=Client())
    assert redirect_https.run(ctx) == []


def test_nothing_listening_on_port_80_passes():
    class Client:
        def get(self, url, follow=True, headers=None):
            raise FetchError("refused")

    ctx = NS(target=NS(scheme="https", host="example.com", url="https://example.com/"), client=Client())
    assert redirect_https.run(ctx) == []
