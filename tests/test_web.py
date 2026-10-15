import json
import pathlib
import time

import pytest
from django.urls import reverse

from siteward.web import state, turnstile, views


@pytest.fixture(autouse=True)
def fresh_state(settings, tmp_path):
    settings.SCAN_MIN_INTERVAL = 0
    settings.ABUSE_LOG_DIR = str(tmp_path / "abuse")
    state.reset()
    yield
    state.reset()


def start_scan(client, server, **extra):
    data = {"url": server.url, "authorised": "on", **extra}
    return client.post(reverse("index"), data)


def wait_done(client, scan_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(reverse("scan_status", args=[scan_id]))
        if response.headers.get("X-Scan-Done") == "1":
            return response
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def scan_id_from(response):
    return response["Location"].rstrip("/").split("/")[-1]


def test_index_renders_form(client):
    response = client.get(reverse("index"))
    assert response.status_code == 200 and b"authorised" in response.content
    assert "no-store" in response.headers["Cache-Control"]


def test_requires_authorisation_checkbox(client, server, settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    response = client.post(reverse("index"), {"url": server.url})
    assert response.status_code == 400 and b"authorised" in response.content


def test_full_scan_flow_and_exports(client, server, settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    state.reset()
    response = start_scan(client, server)
    assert response.status_code == 302
    scan_id = scan_id_from(response)
    page = client.get(reverse("scan_detail", args=[scan_id]))
    assert page.status_code == 200 and "no-store" in page.headers["Cache-Control"]
    done = wait_done(client, scan_id)
    assert b"Grade" in done.content and b"Content-Security-Policy header missing" in done.content
    as_json = client.get(reverse("scan_export", args=[scan_id]) + "?format=json")
    assert json.loads(as_json.content)["target"].startswith("http://127.0.0.1")
    assert "attachment" in as_json.headers["Content-Disposition"] and "no-store" in as_json.headers["Cache-Control"]
    for fmt in ("md", "html"):
        assert client.get(reverse("scan_export", args=[scan_id]) + f"?format={fmt}").status_code == 200
    assert client.get(reverse("scan_export", args=[scan_id]) + "?format=pdf").status_code == 400


def test_hostile_target_data_is_escaped_in_page(client, server, settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    state.reset()
    server.add("/", "<html></html>", headers=[("X-Powered-By", "<img src=x onerror=alert(1)>")])
    scan_id = scan_id_from(start_scan(client, server))
    body = wait_done(client, scan_id).content.decode()
    assert "<img src=x" not in body and "&lt;img src=x" in body


def test_unreachable_target_shows_error_not_500(client, settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    state.reset()
    response = client.post(reverse("index"), {"url": "http://127.0.0.1:1", "authorised": "on"})
    scan_id = scan_id_from(response)
    done = wait_done(client, scan_id)
    assert done.status_code == 200 and b"could not reach" in done.content.lower()


def test_private_target_refused_by_default(client, server):
    response = start_scan(client, server)  # ALLOW_PRIVATE_TARGETS is off by default
    assert response.status_code == 400 and b"Cannot scan" in response.content


def test_unknown_or_expired_scan_is_404_and_stops_polling(client):
    response = client.get(reverse("scan_status", args=["missing"]))
    assert response.status_code == 404 and response.headers["X-Scan-Done"] == "1"
    page = client.get(reverse("scan_detail", args=["missing"]))
    assert page.status_code == 404 and b"not stored" in page.content


# ---- public mode ----------------------------------------------------------------------------

@pytest.fixture
def public(settings, fake_dns, monkeypatch):
    settings.PUBLIC_MODE = True
    settings.TURNSTILE_SECRET = "secret"
    settings.TURNSTILE_SITE_KEY = "site"
    settings.ABUSE_LOG = True
    settings.ABUSE_LOG_KEY = "k"
    settings.RATE_PER_IP = 1
    settings.RATE_PER_TARGET = 100
    fake_dns["example.com"] = "93.184.216.34"
    monkeypatch.setattr(turnstile, "verify", lambda token, ip, secret, post=None: token == "ok")
    captured = []
    monkeypatch.setattr(views, "_run", lambda st, entry: captured.append(entry) or st.slots.release())
    state.reset()
    return captured


def public_post(client, url="https://example.com", **environ):
    data = {"url": url, "authorised": "on", "cf-turnstile-response": "ok", "ports": "on"}
    return client.post(reverse("index"), data, **environ)


def test_public_mode_requires_turnstile(client, public):
    response = client.post(reverse("index"), {"url": "https://example.com", "authorised": "on"})
    assert response.status_code == 400 and public == []


def test_public_mode_forces_port_check_off(client, public):
    assert public_post(client).status_code == 302
    assert public[0].options["ports"] is False


def test_public_mode_rate_limits_per_ip(client, public):
    assert public_post(client).status_code == 302
    assert public_post(client).status_code == 429


def test_spoofed_cf_header_is_ignored_unless_trusted(client, public):
    assert public_post(client, HTTP_CF_CONNECTING_IP="1.1.1.1").status_code == 302
    assert public_post(client, HTTP_CF_CONNECTING_IP="2.2.2.2").status_code == 429  # same real address


def test_cf_header_used_when_trusted(client, public, settings):
    settings.TRUST_CF_HEADERS = True
    state.reset()
    assert public_post(client, HTTP_CF_CONNECTING_IP="1.1.1.1").status_code == 302
    assert public_post(client, HTTP_CF_CONNECTING_IP="2.2.2.2").status_code == 302
    assert public_post(client, HTTP_CF_CONNECTING_IP="1.1.1.1").status_code == 429


def test_public_mode_busy_returns_503(client, public, settings):
    settings.MAX_CONCURRENT_SCANS = 1
    settings.MAX_QUEUE = 0
    settings.RATE_PER_IP = 100
    state.reset()
    state.get().slots.reserve()  # occupy the only slot
    assert public_post(client).status_code == 503


def test_abuse_log_records_ip_and_hashed_target_only(client, public, settings):
    assert public_post(client).status_code == 302
    text = next(pathlib.Path(settings.ABUSE_LOG_DIR).glob("abuse-*.log")).read_text()
    assert '"outcome":"accepted"' in text and "127.0.0.1" in text
    assert "example.com" not in text


def test_public_mode_still_refuses_private_targets(client, public, fake_dns):
    fake_dns["internal.example"] = "10.0.0.7"
    response = public_post(client, url="https://internal.example")
    assert response.status_code == 400 and b"Cannot scan" in response.content


def test_default_theme_is_bootstrap(client):
    assert b"vendor/bootstrap.min.css" in client.get(reverse("index")).content


def test_dashlite_requested_but_absent_falls_back_to_bootstrap(client, settings):
    settings.THEME = "dashlite"
    assert b"vendor/bootstrap.min.css" in client.get(reverse("index")).content


def test_dashlite_used_when_present(client, settings, tmp_path, monkeypatch):
    from siteward.web import context as ctx_module

    fake_root = tmp_path / "static" / "theme" / "dashlite" / "css"
    fake_root.mkdir(parents=True)
    (fake_root / "dashlite.css").write_text("/* stub */")
    monkeypatch.setattr(ctx_module, "BASE_DIR", tmp_path)
    settings.THEME = "dashlite"
    assert b"theme/dashlite/css/dashlite.css" in client.get(reverse("index")).content


def test_store_full_returns_503_and_releases_the_slot(client, public, settings):
    settings.MAX_STORED_SCANS = 1
    settings.RATE_PER_IP = 100
    state.reset()
    assert public_post(client).status_code == 302
    assert public_post(client, url="https://example.com/other").status_code == 503
    assert state.get().slots._n == 0


def test_csrf_flow_works_with_enforced_checks_and_own_cookie_name():
    from django.test import Client

    c = Client(enforce_csrf_checks=True)
    form = c.get(reverse("index"))
    assert "siteward_csrftoken" in form.cookies and "csrftoken" not in form.cookies  # no clash with other local Django apps
    token = form.cookies["siteward_csrftoken"].value
    # a POST without the token is rejected; with the token it is processed (400 = our own validation, not CSRF 403)
    assert c.post(reverse("index"), {"url": "http://example.com"}).status_code == 403
    assert c.post(reverse("index"), {"url": "http://example.com", "csrfmiddlewaretoken": token}).status_code == 400


def test_csrf_failure_page_explains_the_reason_and_how_to_recover(caplog):
    from django.test import Client

    c = Client(enforce_csrf_checks=True)
    with caplog.at_level("WARNING"):
        response = c.post(reverse("index"), {"url": "http://example.com"})  # no cookie, no token
    assert response.status_code == 403
    body = response.content.decode()
    assert "CSRF cookie not set" in body and "reload" in body.lower()
    assert any("csrf rejected" in r.message and "CSRF cookie not set" in r.message for r in caplog.records)
    assert "example.com" not in " ".join(r.message for r in caplog.records)  # never log the target
