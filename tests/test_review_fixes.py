"""Regression tests for the whole-branch review fix pass."""
import socket
import threading
import time
from types import SimpleNamespace as NS

import httpx
import pytest

from webscan.checks import cookies, exposure, headers, leakage, tls
from webscan.core import netguard
from webscan.core.context import build_context
from webscan.core.models import CheckResult, Finding
from webscan.core.netguard import FetchError, GuardedClient
from webscan.core.runner import run_scan
from webscan.reports import to_markdown
from webscan.web.store import Store, StoreFull


# ---- 1. total time is bounded -------------------------------------------------------------

def drip_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()

    def handle(conn):
        try:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(200):
                conn.sendall(b"x")
                time.sleep(0.3)
        except OSError:
            pass
        finally:
            conn.close()

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_slow_drip_response_hits_total_deadline():
    srv, port = drip_server()
    try:
        client = GuardedClient(allow_private=True, min_interval=0, max_duration=1.0)
        start = time.monotonic()
        with pytest.raises(FetchError):
            client.get(f"http://127.0.0.1:{port}/")
        assert time.monotonic() - start < 3.5
    finally:
        srv.close()


def test_runner_uses_daemon_threads_so_a_hung_check_cannot_block_exit(server):
    hang = NS(ID="a.hang", CATEGORY="T", OPT_IN=None, run=lambda ctx: time.sleep(1.5) or [])
    run_scan(server.url, {"allow_private": True, "min_interval": 0}, checks=[hang], timeout=0.2)
    leftovers = [t for t in threading.enumerate() if t.name.startswith("webscan-check") and not t.daemon]
    assert leftovers == []


# ---- 2. soft-404 pages do not produce false positives -------------------------------------

SOFT = ("<html><h1>Whoops! Page not found</h1><p>CREATE TABLE x; INSERT INTO y; phpinfo() <?php [core] "
        "Apache Server Status Traceback (most recent call last)</p></html>")


def test_soft_404_page_with_scary_words_is_not_flagged(server, ctx_for):
    server.add("/", SOFT, headers=[("Content-Type", "text/html")])
    server.set_default(SOFT, headers=[("Content-Type", "text/html")])
    ctx = ctx_for(server)
    assert exposure.run(ctx) == []
    assert leakage.run(ctx) == []


def test_html_response_is_not_accepted_as_a_dump_file(server, ctx_for):
    server.add("/backup.sql", "<html>CREATE TABLE docs</html>", headers=[("Content-Type", "text/html")])
    assert exposure.run(ctx_for(server)) == []


# ---- 3. control characters are neutralised -------------------------------------------------

def test_control_characters_are_stripped_from_findings_and_markdown(sample_report):
    evil = Finding("x", "T\x1b[2J", "C", "low", "a\nb\x1b]0;PWNED\x07", "fix\x9b")
    assert "\x1b" not in evil.title and "\x1b" not in evil.evidence and "\x07" not in evil.evidence
    assert evil.evidence.startswith("a\nb")  # newlines survive
    msg = CheckResult("c", "C", "error", message="boom\x1b[31m").message
    assert "\x1b" not in msg
    sample_report.results[0].findings.append(evil)
    assert "\x1b" not in to_markdown(sample_report)


# ---- 4. https checks follow the final URL ----------------------------------------------------

def redirecting_client(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"

    def handler(request):
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"})
        return httpx.Response(200, content=b"<html></html>", headers={"Set-Cookie": "pref=1; HttpOnly; SameSite=Lax"})

    return GuardedClient(transport=httpx.MockTransport(handler), min_interval=0)


def test_final_target_reflects_redirect_to_https(fake_dns):
    ctx = build_context("http://example.com", {"min_interval": 0}, client=redirecting_client(fake_dns))
    assert ctx.target.scheme == "http" and ctx.final.scheme == "https" and ctx.final.host == "example.com"


def test_https_only_checks_use_final_scheme(fake_dns):
    ctx = build_context("http://example.com", {"min_interval": 0}, client=redirecting_client(fake_dns))
    assert "headers.hsts" in {f.id for f in headers.run(ctx)}
    assert "cookies.secure" in {f.id for f in cookies.run(ctx)}


# ---- 5. connections are pinned to the validated IP ----------------------------------------

def test_tls_connects_to_validated_ip_not_hostname(monkeypatch):
    seen = []

    def fake_connect(address, timeout=None):
        seen.append(address)
        raise OSError("stop")

    monkeypatch.setattr(tls.socket, "create_connection", fake_connect)
    ctx = NS(final=NS(scheme="https", host="example.com", port=443, ips=("93.184.216.34",)))
    with pytest.raises(OSError):
        tls.run(ctx)
    assert seen == [("93.184.216.34", 443)]


def test_http_requests_go_to_validated_ip_with_original_host_and_sni(fake_dns):
    fake_dns["example.com"] = "93.184.216.34"
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers["host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200)

    GuardedClient(transport=httpx.MockTransport(handler), min_interval=0).get("https://example.com/")
    assert seen == [("93.184.216.34", "example.com", "example.com")]


def test_falls_back_to_next_ip_on_connect_error(monkeypatch):
    target = netguard.Target("https://example.com/", "https", "example.com", 443, ("93.184.216.34", "93.184.216.35"))
    monkeypatch.setattr(netguard, "validate_target", lambda url, allow_private=False: target)
    seen = []

    def handler(request):
        seen.append(request.url.host)
        if len(seen) == 1:
            raise httpx.ConnectError("unreachable")
        return httpx.Response(200)

    fetch = GuardedClient(transport=httpx.MockTransport(handler), min_interval=0).get("https://example.com/")
    assert seen == ["93.184.216.34", "93.184.216.35"] and fetch.status == 200


def test_environment_proxies_and_netrc_are_not_used():
    assert GuardedClient()._client.trust_env is False


@pytest.mark.parametrize("ip", ["::a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "2002:7f00:1::", "::ffff:10.0.0.1"])
def test_ipv6_forms_embedding_private_ipv4_are_not_public(ip):
    assert netguard._is_public(ip) is False


@pytest.mark.parametrize("ip", ["2606:4700:4700::1111", "64:ff9b::808:808", "93.184.216.34"])
def test_genuinely_public_addresses_stay_public(ip):
    assert netguard._is_public(ip) is True


# ---- 6. store eviction ----------------------------------------------------------------------

def test_full_store_of_unfinished_scans_refuses_new_ones():
    store = Store(max_entries=2)
    store.create("http://a/", {})
    store.create("http://b/", {})
    with pytest.raises(StoreFull):
        store.create("http://c/", {})


def test_full_store_evicts_finished_entries_first():
    store = Store(max_entries=2)
    running = store.create("http://a/", {})
    done = store.create("http://b/", {})
    done.status, done.finished = "done", time.time()
    store.create("http://c/", {})
    assert store.get(running.id) is running and store.get(done.id) is None


# ---- 11. cookie values never become names ---------------------------------------------------

def test_nameless_cookie_value_is_not_echoed(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "abc123secretvalue; HttpOnly")])
    found = cookies.run(ctx_for(server))
    assert found and all("abc123secretvalue" not in f.title + f.evidence for f in found)


# ---- runner: bounded worker threads (follow-up to background review) ----------------------

def test_runner_never_has_more_than_max_workers_check_threads(server):
    from webscan.core import runner

    checks = [NS(ID=f"slow.{i:02d}", CATEGORY="T", OPT_IN=None, run=lambda ctx: time.sleep(1.0) or [])
              for i in range(20)]
    report = run_scan(server.url, {"allow_private": True, "min_interval": 0}, checks=checks, timeout=0.3)
    live = [t for t in threading.enumerate() if t.name.startswith("webscan-check") and t.is_alive()]
    assert len(live) <= runner.MAX_WORKERS
    assert len(report.results) == 20 and all(r.status == "error" for r in report.results)


def test_unstarted_checks_are_not_run_after_the_deadline(server):
    ran = []
    checks = [NS(ID=f"slow.{i:02d}", CATEGORY="T", OPT_IN=None,
                 run=lambda ctx, i=i: ran.append(i) or time.sleep(0.8) or []) for i in range(20)]
    run_scan(server.url, {"allow_private": True, "min_interval": 0}, checks=checks, timeout=0.2)
    time.sleep(1.2)  # let the abandoned workers finish their current check
    assert len(ran) <= 8  # nothing beyond the first worker batch was ever started
