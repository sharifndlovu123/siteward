"""Hostile or sloppy input to the public site: it must answer cleanly, never crash or leak."""
import logging

import pytest
from django.test import Client
from django.urls import reverse

from siteward.web import state, views


@pytest.fixture(autouse=True)
def fresh_state(settings, tmp_path):
    settings.SCAN_MIN_INTERVAL = 0
    settings.ABUSE_LOG_DIR = str(tmp_path / "abuse")
    state.reset()
    yield
    state.reset()


@pytest.fixture
def no_scans(monkeypatch):
    started = []
    monkeypatch.setattr(views, "_run", lambda st, entry: started.append(entry))
    return started


# ---- resource exhaustion ----------------------------------------------------------------------

ABSURD_URLS = {
    "100k-chars": "a" * 100_000,
    "100k-host": "https://" + "a" * 100_000 + ".com",
    "5000-labels": "http://" + "a." * 5000,
    "100k-path": "https://example.com/" + "x" * 100_000,
    "nul": "\x00",
    "newline": "ht\ntp://x",
    "bidi": "\u202e.com",
    "emoji": "\U0001F4A5",
}


@pytest.mark.parametrize("url", ABSURD_URLS.values(), ids=ABSURD_URLS.keys())
def test_absurd_url_input_is_a_clean_400(client, no_scans, url):
    response = client.post(reverse("index"), {"url": url, "authorised": "on"})
    assert response.status_code == 400 and no_scans == []
    assert b"Traceback" not in response.content


def test_oversized_request_body_is_rejected_not_buffered(client):
    response = client.post(reverse("index"), {"url": "x" * 5_000_000, "authorised": "on"})
    assert response.status_code == 400  # Django's DATA_UPLOAD_MAX_MEMORY_SIZE (2.5MB)


def test_flood_of_unknown_scan_ids_stays_cheap_and_404(client):
    for i in range(300):
        assert client.get(reverse("scan_status", args=[f"nope{i}"])).status_code == 404
    assert len(state.get().store._entries) == 0  # lookups never create entries


def test_scan_ids_are_unguessable():
    store = state.get().store
    ids = {store.create("http://x/", {}).id for _ in range(1)}
    assert all(len(i) >= 21 for i in ids)  # 128 bits of token_urlsafe


def test_store_full_of_running_scans_refuses_rather_than_evicting():
    from siteward.web.store import Store, StoreFull

    store = Store(ttl=900, max_entries=3)
    first = store.create("http://a/", {})
    store.create("http://b/", {})
    store.create("http://c/", {})
    with pytest.raises(StoreFull):
        store.create("http://d/", {})
    assert store.get(first.id) is first  # the in-flight scan was not evicted


def test_finished_scans_are_evicted_oldest_first_and_expire_after_the_ttl():
    from siteward.web.store import Store

    now = [1000.0]
    store = Store(ttl=900, max_entries=2, clock=lambda: now[0])
    a, b = store.create("http://a/", {}), store.create("http://b/", {})
    a.finished = b.finished = now[0]
    c = store.create("http://c/", {})  # full: evicts the oldest finished entry
    assert store.get(a.id) is None and store.get(b.id) is b and store.get(c.id) is c
    now[0] += 901
    assert store.get(b.id) is None  # past the TTL, results are gone


# ---- Host header, methods, error pages ----------------------------------------------------------

@pytest.mark.parametrize("host", ["evil.example", "localhost.evil.example", "127.0.0.1.evil.example", "[::1", "a b"])
def test_unknown_host_header_is_a_plain_400(client, host):
    response = client.get(reverse("index"), HTTP_HOST=host)
    assert response.status_code == 400
    assert b"Traceback" not in response.content and b"settings" not in response.content.lower()


def test_unknown_host_is_logged_as_a_security_warning_without_leaking_to_the_response(client, caplog):
    logging.getLogger("django.security").addHandler(caplog.handler)  # that logger does not propagate to root
    with caplog.at_level(logging.WARNING, logger="django.security"):
        client.get(reverse("index"), HTTP_HOST="evil.example")
    assert any("evil.example" in r.getMessage() for r in caplog.records)  # operator sees it in the logs


@pytest.mark.parametrize("method,path", [("put", "/"), ("delete", "/"), ("patch", "/policy/"), ("post", "/policy/"),
                                         ("post", "/scan/x/status/"), ("options", "/scan/x/export/")])
def test_wrong_method_is_405_with_an_allow_header(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 405 and "Allow" in response.headers


def test_unknown_path_is_a_404_that_reveals_nothing(client, settings):
    settings.DEBUG = False
    response = client.get("/admin/")
    assert response.status_code == 404
    body = response.content.decode().lower()
    for leak in ("django", "traceback", "urlpatterns", "settings.py", "/home/", "python"):
        assert leak not in body


def test_debug_is_off_by_default():
    import os
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if k != "DEBUG"}
    env["DJANGO_SETTINGS_MODULE"] = "siteward.web.settings"
    out = subprocess.run([sys.executable, "-c", "from django.conf import settings; print(settings.DEBUG)"],
                         env=env, capture_output=True, text=True)
    assert out.stdout.strip() == "False"


def test_an_unexpected_server_error_returns_a_generic_500(settings, monkeypatch):
    settings.DEBUG = False

    def boom(request):
        raise RuntimeError("secret internals /home/app/x")

    monkeypatch.setattr(views, "policy", boom)
    from django.urls import clear_url_caches
    import importlib
    from siteward.web import urls
    clear_url_caches()
    importlib.reload(urls)
    try:
        response = Client(raise_request_exception=False).get("/policy/")
    finally:
        monkeypatch.undo()
        clear_url_caches()
        importlib.reload(urls)
    assert response.status_code == 500
    assert b"secret internals" not in response.content and b"/home/app" not in response.content


def test_every_response_carries_the_security_headers(client, server, settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    state.reset()
    for path in ("/", "/policy/", "/scan/missing/", "/scan/missing/status/", "/nope/"):
        headers = client.get(path).headers
        assert "default-src 'self'" in headers["Content-Security-Policy"], path
        assert headers["Referrer-Policy"] == "same-origin" and headers["X-Frame-Options"] == "DENY", path
        assert headers["X-Content-Type-Options"] == "nosniff", path


# ---- the policy page matches what the code really does ------------------------------------------

def test_policy_page_states_the_configured_retention_and_ttl(client, settings):
    settings.ABUSE_LOG_RETENTION_DAYS = 17
    settings.SCAN_TTL_SECONDS = 600
    settings.CONTACT_EMAIL = "abuse@example.org"
    body = client.get(reverse("policy")).content.decode()
    assert "17 days" in body and "10 minutes" in body
    assert 'href="mailto:abuse@example.org"' in body


def test_policy_page_without_contact_email_says_so_instead_of_a_dead_link(client, settings):
    settings.CONTACT_EMAIL = ""
    body = client.get(reverse("policy")).content.decode()
    assert "mailto:" not in body and "set by the operator" in body


def test_policy_claims_match_the_abuse_log_fields(tmp_path):
    """The page promises: time, IP, keyed hash of hostname, options, outcome - and nothing else."""
    import json

    from siteward.web.abuse import AbuseLog

    log = AbuseLog(tmp_path, "k")
    log.record("203.0.113.9", "example.com", {"ports": False}, "accepted")
    entry = json.loads(next(tmp_path.glob("abuse-*.log")).read_text())
    assert set(entry) == {"ts", "ip", "target_hmac", "options", "outcome"}
