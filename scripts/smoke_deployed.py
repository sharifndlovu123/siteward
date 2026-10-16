#!/usr/bin/env python3
"""Post-deploy smoke test and monitor for a running siteward site.

    python scripts/smoke_deployed.py https://scan.example.com [--public] [--min-cert-days 14]

Checks the page, headers, static files, error pages, HTTPS redirect, certificate expiry, and finally runs siteward
against the site itself. Exit code 0 = healthy, 1 = something failed (so cron / CI can alert). Passive: it only
makes ordinary GET requests, plus the same scan any visitor could run against their own site.
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

REQUIRED_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "referrer-policy": "same-origin",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "permissions-policy": "camera=()",
}


class Report:
    def __init__(self):
        self.failures = []

    def check(self, name, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'}  {name}{'  - ' + detail if detail and not ok else ''}")
        if not ok:
            self.failures.append(name)


def cert_days_left(host, port):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock, ctx.wrap_socket(sock, server_hostname=host) as tls:
        not_after = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
    return int((not_after - time.time()) // 86400)


def run(base, public=False, min_cert_days=14, allow_http=False, accept=(), scan=True):
    base = base.rstrip("/")
    parts = urlsplit(base)
    report = Report()
    https = parts.scheme == "https"
    report.check("site is served over https", https or allow_http, "use https:// or pass --allow-http for local runs")

    try:
        _check_http(report, base, parts, https, public, allow_http)
    except httpx.HTTPError as exc:
        report.check("site is reachable", False, f"{type(exc).__name__}: {exc}")
        scan = False  # nothing to scan

    if https:
        host, port = parts.hostname, parts.port or 443
        try:
            days = cert_days_left(host, port)
            report.check(f"certificate valid for {days} more days", days >= min_cert_days, f"renew within {min_cert_days} days")
        except (OSError, ssl.SSLError) as exc:
            report.check("certificate is valid and trusted", False, str(exc))

    if scan:
        from siteward.core.runner import run_scan

        started = time.time()
        result = run_scan(base, {"allow_private": allow_http and parts.hostname in ("127.0.0.1", "localhost"),
                                 "min_interval": 0.05})
        serious = [f for f in result.findings if f.severity in ("critical", "high", "medium") and f.id not in accept]
        report.check(f"siteward finds nothing serious in itself (grade {result.grade}, {time.time() - started:.0f}s)",
                     not serious, "; ".join(f"{f.severity}: {f.title}" for f in serious))
        report.check("self-scan was complete (no errored checks)", not result.incomplete,
                     ", ".join(r.check_id for r in result.results if r.status == "error"))

    print(f"\n{'HEALTHY' if not report.failures else str(len(report.failures)) + ' CHECK(S) FAILED'}  "
          f"{base}  {datetime.now(timezone.utc):%Y-%m-%d %H:%M}Z")
    return 0 if not report.failures else 1


def _check_http(report, base, parts, https, public, allow_http):
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        home = client.get(base + "/")
        report.check("home page returns 200", home.status_code == 200, str(home.status_code))
        report.check("home page is html", "text/html" in home.headers.get("content-type", ""))
        report.check("home page is not cached", "no-store" in home.headers.get("cache-control", ""))
        for name, needle in REQUIRED_HEADERS.items():
            report.check(f"header {name}", needle in home.headers.get(name, ""), home.headers.get(name, "missing"))
        if https:
            report.check("header strict-transport-security", "max-age=" in home.headers.get("strict-transport-security", ""),
                         "set HSTS in Cloudflare (SSL/TLS > Edge Certificates)")

        html = home.text
        report.check("scan form is present", 'name="url"' in html and 'name="authorised"' in html)
        report.check("no port check offered in public mode" if public else "port check offered locally",
                     ('name="ports"' not in html) if public else ('name="ports"' in html))
        report.check("turnstile widget configured" if public else "no turnstile in private mode",
                     ("cf-turnstile" in html) == public)
        report.check("favicon is linked", bool(re.search(r'rel="icon"[^>]*favicon', html)))

        assets = set(re.findall(r'(?:href|src)="(/static/[^"]+)"', html))
        report.check("page references static files", bool(assets))
        for path in sorted(assets):
            r = client.get(urljoin(base + "/", path))
            report.check(f"static file {path}", r.status_code == 200 and len(r.content) > 0, str(r.status_code))

        policy = client.get(base + "/policy/")
        report.check("policy page returns 200", policy.status_code == 200)
        report.check("policy page names a contact" if public else "policy page renders",
                     ("mailto:" in policy.text) if public else True, "set CONTACT_EMAIL")

        missing = client.get(base + "/scan/doesnotexist/")
        body = missing.text.lower()
        report.check("unknown scan is a 404 without leaks", missing.status_code == 404
                     and not any(w in body for w in ("traceback", "django", "/app/", "settings.py")))
        report.check("bad Host header is refused", client.get(base + "/", headers={"Host": "evil.invalid"}).status_code in (400, 403, 404, 421, 526),
                     "ALLOWED_HOSTS may be too permissive")

        if https:
            plain = client.get(f"http://{parts.netloc}/")
            report.check("http redirects to https", plain.status_code in (301, 302, 307, 308)
                         and plain.headers.get("location", "").startswith("https://"), str(plain.status_code))



def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url")
    p.add_argument("--public", action="store_true", help="expect PUBLIC_MODE (Turnstile, no port check, contact email)")
    p.add_argument("--min-cert-days", type=int, default=14)
    p.add_argument("--allow-http", action="store_true", help="local runs only")
    p.add_argument("--accept", action="append", default=[], metavar="FINDING_ID", help="finding id to tolerate (repeatable)")
    p.add_argument("--no-scan", action="store_true", help="skip the self-scan")
    a = p.parse_args(argv)
    return run(a.url, a.public, a.min_cert_days, a.allow_http, set(a.accept), not a.no_scan)


if __name__ == "__main__":
    sys.exit(main())
