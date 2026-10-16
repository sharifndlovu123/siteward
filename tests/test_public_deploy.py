"""Behaviour that only matters once the app is public: abuse resistance, proxy/HTTPS wiring, privacy promises."""
import logging
import os
import pathlib
import stat
import subprocess
import sys
import threading

import pytest
from django.test import Client
from django.urls import reverse

from siteward.web import state, turnstile, views

pytestmark = pytest.mark.usefixtures("fresh_state")


@pytest.fixture
def fresh_state(settings, tmp_path):
    settings.SCAN_MIN_INTERVAL = 0
    settings.ABUSE_LOG_DIR = str(tmp_path / "abuse")
    state.reset()
    yield
    state.reset()


@pytest.fixture
def public(settings, fake_dns, monkeypatch):
    """Public mode with scans stubbed out: the scan thread records the entry and never releases its slot."""
    settings.PUBLIC_MODE = True
    settings.TURNSTILE_SECRET = "secret"
    settings.TURNSTILE_SITE_KEY = "site"
    settings.ABUSE_LOG = True
    settings.ABUSE_LOG_KEY = "k"
    settings.RATE_PER_IP = 1000
    settings.RATE_PER_TARGET = 1000
    fake_dns["example.com"] = "93.184.216.34"
    monkeypatch.setattr(turnstile, "verify", lambda token, ip, secret, post=None: token == "ok")
    started = []
    monkeypatch.setattr(views, "_run", lambda st, entry: started.append(entry))
    state.reset()
    return started


def post(client, url="https://example.com", **environ):
    data = {"url": url, "authorised": "on", "cf-turnstile-response": "ok"}
    return client.post(reverse("index"), data, **environ)


def parallel(n, fn):
    """Run fn(i) in n threads released together; returns the results in order."""
    results, barrier = [None] * n, threading.Barrier(n)

    def worker(i):
        barrier.wait()
        results[i] = fn(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return results


# ---- limits hold under parallel load ---------------------------------------------------------

def test_per_ip_limit_is_exact_under_parallel_requests(public, settings):
    settings.RATE_PER_IP = 5
    state.reset()
    codes = parallel(40, lambda i: post(Client()).status_code)
    assert codes.count(302) == 5 and codes.count(429) == 35


def test_concurrent_scan_cap_holds_under_parallel_requests(public, settings):
    settings.MAX_CONCURRENT_SCANS, settings.MAX_QUEUE = 2, 1
    state.reset()
    codes = parallel(30, lambda i: post(Client()).status_code)
    assert codes.count(302) == 3 and codes.count(503) == 27  # 2 running + 1 queued, never more
    assert len(public) == 3


def test_per_target_limit_holds_across_different_ips(public, settings):
    settings.RATE_PER_TARGET = 3
    state.reset()
    codes = parallel(20, lambda i: post(Client(), REMOTE_ADDR=f"198.51.100.{i + 1}").status_code)
    assert codes.count(302) == 3 and codes.count(429) == 17


# ---- client IP trust -------------------------------------------------------------------------

def test_trusted_cf_mode_falls_back_to_the_socket_address_without_the_header(public, settings):
    settings.TRUST_CF_HEADERS = True
    settings.RATE_PER_IP = 1
    state.reset()
    assert post(Client()).status_code == 302
    assert post(Client()).status_code == 429  # same REMOTE_ADDR, no header: still limited


def test_untrusted_mode_cannot_dodge_the_limit_with_many_forged_headers(public, settings):
    settings.RATE_PER_IP = 2
    state.reset()
    codes = [post(Client(), HTTP_CF_CONNECTING_IP=f"203.0.113.{i}").status_code for i in range(10)]
    assert codes.count(302) == 2


# ---- SSRF through the public form ------------------------------------------------------------

SSRF_TARGETS = [
    "http://localhost", "http://127.0.0.1", "http://127.1", "http://0", "http://0.0.0.0",
    "http://2130706433", "http://0x7f000001", "http://017700000001", "http://[::1]", "http://[::ffff:127.0.0.1]",
    "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1", "http://192.168.1.1", "http://172.16.0.1",
    "http://100.64.0.1", "file:///etc/passwd", "gopher://127.0.0.1:6379/_PING", "ftp://example.com",
    "http://user:pass@example.com", "javascript:alert(1)", "http://",
]


@pytest.mark.parametrize("target", SSRF_TARGETS)
def test_public_form_refuses_internal_and_odd_targets(public, target):
    response = post(Client(), url=target)
    assert response.status_code == 400, target
    assert public == []  # no scan was ever started


def test_allow_private_env_is_ignored_in_public_mode(public, settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    state.reset()
    assert post(Client(), url="http://127.0.0.1").status_code == 400
    assert public == []


def test_public_hostname_resolving_to_a_private_address_is_refused(public, fake_dns):
    fake_dns["rebind.example"] = "169.254.169.254"
    assert post(Client(), url="https://rebind.example").status_code == 400
    assert public == []


# ---- proxy / HTTPS wiring (browser sees https, the container sees plain http) ------------------

HOST = "siteward.example"


def _csrf_post(settings, trusted, origin="https://" + HOST):
    settings.ALLOWED_HOSTS = [HOST]
    settings.CSRF_TRUSTED_ORIGINS = trusted
    client = Client(enforce_csrf_checks=True)
    form = client.get(reverse("index"), HTTP_HOST=HOST)
    token = form.cookies["siteward_csrftoken"].value
    return client.post(reverse("index"), {"url": "http://", "csrfmiddlewaretoken": token},
                       HTTP_HOST=HOST, HTTP_ORIGIN=origin, HTTP_X_FORWARDED_PROTO="https")


def test_https_origin_behind_a_proxy_needs_csrf_trusted_origins(settings):
    assert _csrf_post(settings, trusted=[]).status_code == 403  # the symptom of a missing CSRF_TRUSTED_ORIGINS


def test_https_origin_behind_a_proxy_works_when_trusted(settings):
    assert _csrf_post(settings, trusted=["https://" + HOST]).status_code == 400  # 400 = our validation, not CSRF


def test_foreign_origin_is_rejected_even_when_another_origin_is_trusted(settings):
    assert _csrf_post(settings, trusted=["https://" + HOST], origin="https://evil.example").status_code == 403


def test_csrf_cookie_is_secure_and_httponly_in_public_mode(settings):
    settings.CSRF_COOKIE_SECURE = True
    cookie = Client().get(reverse("index")).cookies["siteward_csrftoken"]
    assert cookie["secure"] and cookie["httponly"]


def test_public_mode_refuses_to_start_without_its_secrets():
    env = {k: v for k, v in os.environ.items() if k not in ("TURNSTILE_SECRET", "TURNSTILE_SITE_KEY", "ABUSE_LOG_KEY")}
    env.update(PUBLIC_MODE="1", DJANGO_SETTINGS_MODULE="siteward.web.settings")
    proc = subprocess.run([sys.executable, "-c", "import siteward.web.settings"], env=env, capture_output=True, text=True)
    assert proc.returncode != 0 and "PUBLIC_MODE requires" in proc.stderr


# ---- the abuse log keeps its privacy promises ---------------------------------------------------

def _log_text(settings):
    return "".join(p.read_text() for p in pathlib.Path(settings.ABUSE_LOG_DIR).glob("abuse-*.log"))


def test_abuse_log_is_private_to_the_app_user(public, settings):
    post(Client())
    directory = pathlib.Path(settings.ABUSE_LOG_DIR)
    logfile = next(directory.glob("abuse-*.log"))
    assert stat.S_IMODE(logfile.stat().st_mode) == 0o600  # it holds client IPs
    assert stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0


def test_no_outcome_logs_the_plaintext_target(public, settings, fake_dns, caplog, capfd):
    fake_dns["secret-target.example"] = "93.184.216.35"
    fake_dns["internal.secret.example"] = "10.0.0.9"
    settings.RATE_PER_TARGET = 1
    state.reset()
    with caplog.at_level(logging.DEBUG):
        post(Client(), url="https://secret-target.example/private/path?token=abc")   # accepted
        post(Client(), url="https://secret-target.example/private/path?token=abc")   # rate limited
        post(Client(), url="https://internal.secret.example")                         # blocked
        Client().post(reverse("index"), {"url": "https://secret-target.example", "authorised": "on",
                                         "cf-turnstile-response": "bad"})               # captcha failed
    everything = _log_text(settings) + capfd.readouterr().out + capfd.readouterr().err + \
        " ".join(r.getMessage() for r in caplog.records)
    for secret in ("secret-target", "internal.secret", "private/path", "token=abc"):
        assert secret not in everything
    for outcome in ("accepted", "rate_limited", "blocked", "captcha_failed"):
        assert f'"outcome":"{outcome}"' in _log_text(settings)  # every path was exercised and logged


def test_same_host_gets_a_different_hash_under_a_different_key(tmp_path):
    from siteward.web.abuse import AbuseLog

    assert AbuseLog(tmp_path, "key-a").target_hmac("example.com") != AbuseLog(tmp_path, "key-b").target_hmac("example.com")
