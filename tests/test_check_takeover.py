from types import SimpleNamespace as NS

import pytest

from webscan.checks import takeover
from webscan.core.models import Skip


def ctx(host="shop.example.com", body=""):
    return NS(target=NS(host=host), baseline=NS(text=body))


def test_no_cname_is_clean(monkeypatch):
    monkeypatch.setattr(takeover, "_cname", lambda name: None)
    assert takeover.run(ctx()) == []


def test_dangling_cname_is_high(monkeypatch):
    monkeypatch.setattr(takeover, "_cname", lambda name: "gone.example.net")
    monkeypatch.setattr(takeover, "_exists", lambda name: False)
    found = takeover.run(ctx())
    assert [(f.id, f.severity) for f in found] == [("takeover.dangling-cname", "high")]


def test_provider_fingerprint_is_high(monkeypatch):
    monkeypatch.setattr(takeover, "_cname", lambda name: "acme.github.io")
    monkeypatch.setattr(takeover, "_exists", lambda name: True)
    found = takeover.run(ctx(body="<h1>There isn't a GitHub Pages site here.</h1>"))
    assert [f.id for f in found] == ["takeover.unclaimed-service"]


def test_healthy_provider_cname_is_clean(monkeypatch):
    monkeypatch.setattr(takeover, "_cname", lambda name: "acme.github.io")
    monkeypatch.setattr(takeover, "_exists", lambda name: True)
    assert takeover.run(ctx(body="<h1>Welcome</h1>")) == []


def test_ip_targets_are_skipped():
    with pytest.raises(Skip):
        takeover.run(ctx(host="93.184.216.34"))
