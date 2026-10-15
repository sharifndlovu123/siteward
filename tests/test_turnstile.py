import httpx

from siteward.web.turnstile import verify


class Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def test_success():
    calls = []

    def post(url, data, timeout):
        calls.append(data)
        return Resp({"success": True})

    assert verify("tok", "1.2.3.4", "sec", post=post) is True
    assert calls[0] == {"secret": "sec", "response": "tok", "remoteip": "1.2.3.4"}


def test_failure_empty_token_and_errors():
    assert verify("tok", "1.2.3.4", "sec", post=lambda *a, **k: Resp({"success": False})) is False
    assert verify("", "1.2.3.4", "sec", post=lambda *a, **k: Resp({"success": True})) is False

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    assert verify("tok", "1.2.3.4", "sec", post=boom) is False
