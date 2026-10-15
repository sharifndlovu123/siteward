# siteward v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `siteward`, a small open-source Python tool that runs passive security checks (plus an opt-in port check) against a URL and shows/exports the findings, via a CLI and a Django web UI, storing nothing about scanned sites.

**Architecture:** A framework-free scanner (`core/` + `checks/` + `reports/`) that both a Typer CLI and a database-less Django app call. Checks are one-module plugins discovered at runtime. The web app keeps results in an in-memory TTL store, runs scans in background threads, and (in public mode) adds layered in-memory rate limiting, Turnstile, and a minimal HMAC-keyed abuse log.

**Tech Stack:** Python 3.11+, Django (no database), Typer, httpx, dnspython, Jinja2, WhiteNoise, gunicorn, pytest + pytest-django.

**Spec:** `docs/superpowers/specs/2026-10-15-web-security-scanner-design.md` and `docs/superpowers/specs/architecture.md` (read both; section 10 of the architecture doc covers public hosting).

## Global Constraints

- Python `>=3.11`; package name `siteward`; MIT licence; copyright "DevBridge (Pty) Ltd".
- Runtime dependencies are limited to: `django`, `httpx`, `dnspython`, `jinja2`, `typer` (with a `click>=8.2` floor), `whitenoise`, `gunicorn`. Dev: `pytest`, `pytest-django`. Add nothing else.
- **No database and no scan data on disk.** Django has `DATABASES = {}`; no sessions/auth apps. Results live in process memory only (TTL 15 min, max 20 entries).
- Default scans are **passive**. The port check is opt-in (`ports` option) and **forced off in `PUBLIC_MODE`**.
- `core/` and `checks/` never import Django or Typer; `web/` and `cli/` contain no scan logic.
- All outbound requests from checks go through `GuardedClient` (private/loopback/link-local/metadata targets refused, re-validated on every redirect hop, bodies capped at 2 MB, global request pacing).
- Finding evidence must **never contain secret values** (e.g. contents of `.env`, cookie values).
- Logs never contain target URLs, findings, evidence, or reports. The only exception is the abuse log: `{ts, client_ip, target_hmac, options, outcome}`, 30-day retention.
- Tests must not touch the internet (use the local fake server, `httpx.MockTransport`, and monkeypatched DNS).
- DashLite (commercial) files are never committed; `siteward/web/static/theme/dashlite/` is git-ignored.
- Commits: use `git commit -m "<message>" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"`.

## Review Focus

Inputs the spec implies but that are easy to get wrong; each has a pinning test in the task named.

- **Soft-404 sites** (every path returns 200 HTML): exposure and policy checks must report nothing false. Task 6 (`test_exposure.py`), Task 5 (`test_policy_files.py`).
- **Redirects or DNS names that point at internal addresses** (`169.254.169.254`, `10.x`, a hostname resolving to `127.0.0.1`): refused, never fetched. Task 3.
- **Hostile target data in findings** (`<script>`, backticks, newlines in header values/cookie names): escaped in HTML/Markdown exports and the web page, never executed. Tasks 7 and 9b.
- **Misbehaving targets** (connection refused, 5 MB / endless body, check that hangs or crashes): clear error (CLI exit 2, error panel on web), bounded memory, no 500s, scan completes. Tasks 3, 4, 8, 9b.
- **Discovered secrets** (`.env` with passwords): reported as exposed, but the secret value is never copied into the report. Task 6.

---

## File Structure

```
pyproject.toml  LICENSE  README.md  CONTRIBUTING.md  SECURITY.md  Dockerfile  .gitignore
siteward/
  __init__.py                 __version__
  core/
    models.py                 Finding, CheckResult, ScanReport, Skip, SEVERITIES, severity_rank
    netguard.py               validate_target, GuardedClient, Fetch, Target, BlockedTarget, FetchError
    context.py                ScanContext, build_context
    runner.py                 discover_checks, run_scan, ScanError
  checks/                     one module per check (headers, cookies, cors, leakage, redirect_https,
                              policy_files, exposure, tls, dns_email, takeover, ports)
  reports/
    __init__.py               FORMATS, render
    json_report.py  markdown_report.py  html_report.py  report.html.j2
  cli/
    __init__.py  main.py
  web/
    settings.py urls.py wsgi.py state.py store.py limits.py abuse.py turnstile.py
    views.py context.py middleware.py
    templates/  (base_bootstrap.html base_dashlite.html index.html scan.html _results.html policy.html)
    static/     (js/poll.js, vendor/bootstrap.min.css, theme/ (git-ignored dashlite))
tests/
  __init__.py conftest.py fake_server.py
  test_models.py test_netguard.py test_runner.py test_check_*.py test_reports.py test_cli.py
  test_store.py test_limits.py test_abuse.py test_turnstile.py test_web.py
```

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`, `LICENSE`, `.gitignore`, `README.md` (stub), `siteward/__init__.py`, `siteward/core/__init__.py`, `siteward/checks/__init__.py`, `siteward/reports/__init__.py` (empty for now), `siteward/cli/__init__.py`, `siteward/web/__init__.py`, `tests/__init__.py`

**Interfaces:**
- Produces: importable package `siteward` with `siteward.__version__ == "0.1.0"`; a venv with dev dependencies installed; a git repo.

- [ ] **Step 1: Initialise git and the virtualenv**

```bash
cd /home/sharif/Documents/vs_code/work/devbridge/web_test
git init
python3 -m venv .venv
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "siteward"
version = "0.1.0"
description = "Small, self-hostable passive web security scanner"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = [
  "django>=5.0",
  "httpx>=0.27",
  "dnspython>=2.6",
  "jinja2>=3.1",
  "typer>=0.12",
  "click>=8.2",   # floor only: CliRunner separates stdout/stderr from 8.2 (tests rely on it)
  "whitenoise>=6.6",
  "gunicorn>=22",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-django>=4.8"]

[project.scripts]
siteward = "siteward.cli.main:app"

[tool.setuptools.packages.find]
include = ["siteward*"]

[tool.setuptools.package-data]
siteward = ["reports/*.j2", "web/templates/**/*", "web/static/**/*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
DJANGO_SETTINGS_MODULE = "siteward.web.settings"
```

- [ ] **Step 3: Write `.gitignore`, `LICENSE`, stub `README.md`, package inits**

`.gitignore`:
```
.venv/
__pycache__/
*.egg-info/
.pytest_cache/
staticfiles/
*.log
.env
# Commercial theme: never commit (see README "Themes")
siteward/web/static/theme/dashlite/
```

`LICENSE`:
```
MIT License

Copyright (c) 2026 DevBridge (Pty) Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

`README.md`: `# siteward` followed by one line `Work in progress; full docs land in the final task.`

`siteward/__init__.py`: `__version__ = "0.1.0"`. All other `__init__.py` files and `tests/__init__.py`: empty.

- [ ] **Step 4: Install and verify**

```bash
. .venv/bin/activate
pip install -e '.[dev]'
python -c "import siteward; print(siteward.__version__)"
pytest -q
```
Expected: prints `0.1.0`; pytest reports `no tests ran` (exit code 5 is fine here).

- [ ] **Step 5: Commit (include the existing docs)**

```bash
git add -A
git commit -m "chore: project scaffold, licence, docs" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Core data models

**Files:**
- Create: `siteward/core/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `SEVERITIES = ("info","low","medium","high","critical")`, `severity_rank(s: str) -> int`
  - `class Skip(Exception)`
  - `@dataclass Finding(id, title, category, severity, evidence="", remediation="")` (raises `ValueError` on unknown severity)
  - `@dataclass CheckResult(check_id, category, status, findings=[], message="")`, status in `passed|findings|skipped|error`
  - `@dataclass ScanReport(target, started, finished, version, options, results)` with properties `findings` (most severe first), `counts` (dict, all severities), `grade` (`A`..`F`), `incomplete` (bool: any error result) and `to_dict() -> dict` (JSON-serialisable)

- [ ] **Step 1: Write the failing test**

`tests/test_models.py`:
```python
import json
from datetime import datetime, timezone

import pytest

from siteward.core.models import CheckResult, Finding, ScanReport, severity_rank

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def finding(sev, fid="x"):
    return Finding(fid, f"title {fid}", "Cat", sev, "evidence", "fix")


def report(results):
    return ScanReport("http://example.com/", NOW, NOW, "0.1.0", {"ports": False}, results)


def test_unknown_severity_rejected():
    with pytest.raises(ValueError):
        finding("urgent")


def test_severity_rank_orders():
    assert severity_rank("info") < severity_rank("low") < severity_rank("critical")


def test_findings_sorted_most_severe_first():
    r = report([CheckResult("a", "C", "findings", [finding("low", "1"), finding("high", "2"), finding("medium", "3")])])
    assert [f.severity for f in r.findings] == ["high", "medium", "low"]


def test_counts_include_all_severities():
    r = report([CheckResult("a", "C", "findings", [finding("low"), finding("low")])])
    assert r.counts == {"info": 0, "low": 2, "medium": 0, "high": 0, "critical": 0}


@pytest.mark.parametrize(
    "severities,grade",
    [([], "A"), (["info"], "A"), (["low"], "B"), (["low", "medium"], "C"), (["high"], "D"), (["medium", "critical"], "F")],
)
def test_grade_is_driven_by_worst_finding(severities, grade):
    r = report([CheckResult("a", "C", "findings", [finding(s) for s in severities])])
    assert r.grade == grade


def test_incomplete_when_a_check_errored():
    ok = report([CheckResult("a", "C", "passed")])
    bad = report([CheckResult("a", "C", "error", message="boom")])
    assert ok.incomplete is False and bad.incomplete is True


def test_to_dict_is_json_serialisable():
    r = report([CheckResult("a", "C", "findings", [finding("low")]), CheckResult("b", "C", "skipped", message="n/a")])
    data = json.loads(json.dumps(r.to_dict()))
    assert data["grade"] == "B"
    assert data["results"][0]["findings"][0]["severity"] == "low"
    assert data["started"].startswith("2026-10-15")
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'siteward.core.models'`

- [ ] **Step 3: Implement**

`siteward/core/models.py`:
```python
"""Plain data types shared by every layer. No framework imports."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {name: i for i, name in enumerate(SEVERITIES)}
_GRADE = {"info": "A", "low": "B", "medium": "C", "high": "D", "critical": "F"}


def severity_rank(severity: str) -> int:
    return _RANK[severity]


class Skip(Exception):
    """Raised by a check that does not apply to this target."""


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    evidence: str = ""
    remediation: str = ""

    def __post_init__(self):
        if self.severity not in _RANK:
            raise ValueError(f"unknown severity: {self.severity!r}")


@dataclass
class CheckResult:
    check_id: str
    category: str
    status: str  # passed | findings | skipped | error
    findings: list[Finding] = field(default_factory=list)
    message: str = ""


@dataclass
class ScanReport:
    target: str
    started: datetime
    finished: datetime
    version: str
    options: dict
    results: list[CheckResult]

    @property
    def findings(self) -> list[Finding]:
        found = [f for r in self.results for f in r.findings]
        return sorted(found, key=lambda f: -_RANK[f.severity])

    @property
    def counts(self) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def grade(self) -> str:
        found = self.findings
        return _GRADE[found[0].severity] if found else "A"

    @property
    def incomplete(self) -> bool:
        return any(r.status == "error" for r in self.results)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started": self.started.isoformat(),
            "finished": self.finished.isoformat(),
            "version": self.version,
            "options": self.options,
            "grade": self.grade,
            "incomplete": self.incomplete,
            "counts": self.counts,
            "results": [
                {
                    "check_id": r.check_id,
                    "category": r.category,
                    "status": r.status,
                    "message": r.message,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in self.results
            ],
        }
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add siteward/core/models.py tests/test_models.py
git commit -m "feat(core): finding, check result and report models" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Test fixtures and `netguard` (the safety layer)

**Files:**
- Create: `tests/fake_server.py`, `tests/conftest.py`, `siteward/core/netguard.py`
- Test: `tests/test_netguard.py`

**Interfaces:**
- Produces (`siteward.core.netguard`):
  - `USER_AGENT: str`, `MAX_BODY = 2*1024*1024`, `MAX_REDIRECTS = 5`
  - `class BlockedTarget(ValueError)`, `class FetchError(Exception)`
  - `@dataclass(frozen=True) Target(url, scheme, host, port, ips: tuple[str, ...])`
  - `validate_target(raw_url: str, allow_private: bool = False) -> Target`
  - `@dataclass Fetch(url, status, headers: httpx.Headers, body: bytes, chain: list[str])` with `.text`
  - `GuardedClient(allow_private=False, min_interval=0.05, timeout=10.0, transport=None)` with `.get(url, follow=True, headers=None) -> Fetch` and `.close()`
- Produces (tests): `FakeServer` (`.add(path, body="", status=200, headers=None)`, `.set_default(...)`, `.banner`, `.url`, `.requests`), fixtures `server` and `fake_dns` (dict `host -> ip`).

- [ ] **Step 1: Write the test fixtures**

`tests/fake_server.py`:
```python
"""Tiny local HTTP server for tests. Nothing here touches the internet."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeServer:
    def __init__(self):
        self.routes = {}
        self.default = (404, [("Content-Type", "text/plain")], b"not found")
        self.banner = "fake"
        self.requests = []  # (method, path, headers)
        self._httpd = None
        self.url = ""
        self.add("/", "<html><body>ok</body></html>", headers=[("Content-Type", "text/html")])

    def add(self, path, body="", status=200, headers=None):
        if isinstance(body, str):
            body = body.encode()
        if isinstance(headers, dict):
            headers = list(headers.items())
        self.routes[path] = (status, list(headers or []), body)

    def set_default(self, body="", status=200, headers=None):
        if isinstance(body, str):
            body = body.encode()
        if isinstance(headers, dict):
            headers = list(headers.items())
        self.default = (status, list(headers or []), body)

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def version_string(self):
                return outer.banner

            def _serve(self, head_only):
                path = self.path.split("?")[0]
                outer.requests.append((self.command, path, dict(self.headers)))
                status, headers, body = outer.routes.get(path, outer.default)
                self.send_response(status)
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)

            def do_GET(self):
                self._serve(False)

            def do_HEAD(self):
                self._serve(True)

            def log_message(self, *args):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
```

`tests/conftest.py`:
```python
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
```

- [ ] **Step 2: Write the failing netguard tests**

`tests/test_netguard.py`:
```python
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
    assert seen == ["https://example.com/"]  # the internal address was never requested


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
```

- [ ] **Step 3: Run to verify it fails**

Run: `pytest tests/test_netguard.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'siteward.core.netguard'`

- [ ] **Step 4: Implement**

`siteward/core/netguard.py`:
```python
"""Safety layer: every outbound request in the project goes through here.

Known limit: DNS is resolved once for validation and again by the HTTP stack, so a
hostile resolver could in theory rebind between the two. Acceptable for v1 (documented).
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

USER_AGENT = "siteward/0.1 (passive security scanner)"
MAX_BODY = 2 * 1024 * 1024
MAX_REDIRECTS = 5
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class BlockedTarget(ValueError):
    """The target is not allowed to be scanned."""


class FetchError(Exception):
    """The target could not be fetched (network error, too many redirects, ...)."""


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    ips: tuple


def _is_public(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def validate_target(raw_url: str, allow_private: bool = False) -> Target:
    raw = (raw_url or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise BlockedTarget("invalid URL") from None
    if parts.scheme not in ("http", "https"):
        raise BlockedTarget("only http and https URLs are allowed")
    if parts.username or parts.password:
        raise BlockedTarget("URLs with credentials are not allowed")
    if not parts.hostname:
        raise BlockedTarget("URL has no host")

    host = parts.hostname.rstrip(".").lower()
    port = port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise BlockedTarget(f"cannot resolve host: {host}") from None
    ips = tuple(dict.fromkeys(info[4][0] for info in infos))
    if not ips:
        raise BlockedTarget(f"cannot resolve host: {host}")
    if not allow_private:
        private = [ip for ip in ips if not _is_public(ip)]
        if private:
            raise BlockedTarget("target resolves to a private or internal address")

    default_port = 443 if parts.scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host
    netloc = shown if port == default_port else f"{shown}:{port}"
    url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
    return Target(url, parts.scheme, host, port, ips)


@dataclass
class Fetch:
    url: str  # final URL after redirects
    status: int
    headers: httpx.Headers
    body: bytes
    chain: list

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class GuardedClient:
    def __init__(self, allow_private=False, min_interval=0.05, timeout=10.0, transport=None):
        self.allow_private = allow_private
        self._min_interval = min_interval
        self._lock = threading.Lock()
        self._last = 0.0
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            transport=transport,
        )

    def close(self):
        self._client.close()

    def _pace(self):
        with self._lock:
            wait = self._last + self._min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    @staticmethod
    def _read_capped(response) -> bytes:
        buf = bytearray()
        for chunk in response.iter_bytes():
            buf.extend(chunk)
            if len(buf) >= MAX_BODY:
                del buf[MAX_BODY:]
                break
        return bytes(buf)

    def get(self, url: str, follow: bool = True, headers: dict | None = None) -> Fetch:
        chain = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            validate_target(current, self.allow_private)  # re-validated on every hop
            chain.append(current)
            self._pace()
            try:
                with self._client.stream("GET", current, headers=headers) as response:
                    body = self._read_capped(response)
                    status, response_headers = response.status_code, response.headers
            except httpx.HTTPError as exc:
                raise FetchError(f"{type(exc).__name__}: {exc}") from exc
            location = response_headers.get("location")
            if follow and status in _REDIRECT_STATUSES and location:
                current = urljoin(current, location)
                continue
            return Fetch(current, status, response_headers, body, chain)
        raise FetchError("too many redirects")
```

- [ ] **Step 5: Run to verify it passes, then commit**

Run: `pytest tests/test_netguard.py -v`
Expected: all PASS

```bash
git add tests/fake_server.py tests/conftest.py siteward/core/netguard.py tests/test_netguard.py
git commit -m "feat(core): netguard safety layer and test fixtures" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Scan context and runner

**Files:**
- Create: `siteward/core/context.py`, `siteward/core/runner.py`
- Modify: `tests/conftest.py` (add `ctx_for` fixture)
- Test: `tests/test_runner.py`

**Interfaces:**
- Consumes: `models` (Task 2), `netguard` (Task 3).
- Produces:
  - `ScanContext(target: Target, client: GuardedClient, baseline: Fetch, options: dict)`
  - `build_context(url, options=None, client=None) -> ScanContext`; options keys used: `allow_private`, `min_interval`, `ports`. May raise `BlockedTarget` / `FetchError`.
  - `class ScanError(Exception)`
  - `discover_checks() -> list[module]`: modules in `siteward.checks` that define `ID`, `CATEGORY`, `OPT_IN` (None or an option name) and `run(ctx) -> list[Finding]`
  - `run_scan(url, options=None, on_result=None, checks=None, timeout=60.0, client=None) -> ScanReport`; raises `BlockedTarget` (refused) or `ScanError` (unreachable). Checks that raise become `error` results, `Skip` becomes `skipped`, disabled opt-in checks become `skipped`, unfinished checks at timeout become `error`.
  - fixture `ctx_for(server, **options) -> ScanContext` (allow_private on, no pacing).

- [ ] **Step 1: Add the `ctx_for` fixture**

Append to `tests/conftest.py`:
```python
from siteward.core.context import build_context  # noqa: E402


@pytest.fixture
def ctx_for():
    def make(server, **options):
        opts = {"allow_private": True, "min_interval": 0}
        opts.update(options)
        return build_context(server.url, opts)

    return make
```

- [ ] **Step 2: Write the failing tests**

`tests/test_runner.py`:
```python
import socket
import time
from types import SimpleNamespace as NS

import pytest

from siteward.core.models import Finding, Skip
from siteward.core.netguard import BlockedTarget
from siteward.core.runner import ScanError, run_scan

OPTS = {"allow_private": True, "min_interval": 0}


def check(check_id, fn, opt_in=None):
    return NS(ID=check_id, CATEGORY="T", OPT_IN=opt_in, run=fn)


def finding():
    return Finding("t.f", "A finding", "T", "low", "ev", "fix")


def by_id(report):
    return {r.check_id: r for r in report.results}


def test_statuses_for_pass_findings_skip_and_crash(server):
    def crash(ctx):
        raise RuntimeError("boom")

    def skip(ctx):
        raise Skip("not applicable")

    checks = [
        check("a.pass", lambda ctx: []),
        check("b.find", lambda ctx: [finding()]),
        check("c.skip", skip),
        check("d.crash", crash),
    ]
    report = run_scan(server.url, OPTS, checks=checks)
    results = by_id(report)
    assert results["a.pass"].status == "passed"
    assert results["b.find"].status == "findings" and len(results["b.find"].findings) == 1
    assert results["c.skip"].status == "skipped" and "not applicable" in results["c.skip"].message
    assert results["d.crash"].status == "error" and "RuntimeError" in results["d.crash"].message
    assert report.incomplete is True


def test_opt_in_check_skipped_unless_enabled(server):
    calls = []
    opt = check("p.ports", lambda ctx: calls.append(1) or [], opt_in="ports")
    off = run_scan(server.url, OPTS, checks=[opt])
    assert by_id(off)["p.ports"].status == "skipped" and calls == []
    on = run_scan(server.url, {**OPTS, "ports": True}, checks=[opt])
    assert by_id(on)["p.ports"].status == "passed" and calls == [1]


def test_hanging_check_times_out_without_blocking_the_scan(server):
    checks = [check("a.fast", lambda ctx: []), check("b.hang", lambda ctx: time.sleep(2) or [])]
    start = time.monotonic()
    report = run_scan(server.url, OPTS, checks=checks, timeout=0.3)
    assert time.monotonic() - start < 1.5
    results = by_id(report)
    assert results["a.fast"].status == "passed"
    assert results["b.hang"].status == "error" and "timed out" in results["b.hang"].message


def test_on_result_called_once_per_check(server):
    seen = []
    checks = [check("a", lambda ctx: []), check("b", lambda ctx: [finding()])]
    run_scan(server.url, OPTS, on_result=seen.append, checks=checks)
    assert sorted(r.check_id for r in seen) == ["a", "b"]


def test_report_metadata_and_public_options(server):
    report = run_scan(server.url, {**OPTS, "ports": True}, checks=[check("a", lambda ctx: [])])
    assert report.target == server.url + "/"
    assert report.options == {"ports": True}
    assert report.started <= report.finished and report.version


def test_unreachable_target_raises_scan_error():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here now
    with pytest.raises(ScanError):
        run_scan(f"http://127.0.0.1:{port}", OPTS, checks=[])


def test_private_target_refused_without_allow_private(server):
    with pytest.raises(BlockedTarget):
        run_scan(server.url, {"min_interval": 0}, checks=[])
```

- [ ] **Step 3: Run to verify it fails**

Run: `pytest tests/test_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'siteward.core.context'`

- [ ] **Step 4: Implement**

`siteward/core/context.py`:
```python
from __future__ import annotations

from dataclasses import dataclass

from .netguard import Fetch, GuardedClient, Target, validate_target


@dataclass
class ScanContext:
    target: Target
    client: GuardedClient
    baseline: Fetch
    options: dict


def build_context(url: str, options: dict | None = None, client: GuardedClient | None = None) -> ScanContext:
    """Validate the target and fetch the baseline page once. May raise BlockedTarget or FetchError."""
    options = dict(options or {})
    allow_private = bool(options.get("allow_private"))
    target = validate_target(url, allow_private)
    client = client or GuardedClient(allow_private=allow_private, min_interval=options.get("min_interval", 0.05))
    baseline = client.get(target.url)
    return ScanContext(target, client, baseline, options)
```

`siteward/core/runner.py`:
```python
from __future__ import annotations

import importlib
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import datetime, timezone

from siteward import __version__

from .context import build_context
from .models import CheckResult, ScanReport, Skip
from .netguard import FetchError

MAX_WORKERS = 8


class ScanError(Exception):
    """The scan could not start (target unreachable)."""


def discover_checks() -> list:
    import siteward.checks as package

    modules = []
    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{info.name}")
        if hasattr(module, "ID") and hasattr(module, "run"):
            modules.append(module)
    return sorted(modules, key=lambda m: m.ID)


def _run_one(module, ctx) -> CheckResult:
    opt_in = getattr(module, "OPT_IN", None)
    if opt_in and not ctx.options.get(opt_in):
        return CheckResult(module.ID, module.CATEGORY, "skipped", message=f"opt-in check; not enabled ({opt_in})")
    try:
        findings = list(module.run(ctx))
    except Skip as skip:
        return CheckResult(module.ID, module.CATEGORY, "skipped", message=str(skip))
    except Exception as exc:  # a crashing check must never look like a pass
        return CheckResult(module.ID, module.CATEGORY, "error", message=f"{type(exc).__name__}: {exc}")
    return CheckResult(module.ID, module.CATEGORY, "findings" if findings else "passed", findings=findings)


def run_scan(url, options=None, on_result=None, checks=None, timeout=60.0, client=None) -> ScanReport:
    options = dict(options or {})
    started = datetime.now(timezone.utc)
    try:
        ctx = build_context(url, options, client=client)  # BlockedTarget propagates
    except FetchError as exc:
        raise ScanError(f"could not reach the target: {exc}") from exc

    modules = checks if checks is not None else discover_checks()
    results: list[CheckResult] = []

    def emit(result: CheckResult):
        results.append(result)
        if on_result:
            on_result(result)

    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures = {pool.submit(_run_one, module, ctx): module for module in modules}
    finished = set()
    try:
        for future in as_completed(futures, timeout=timeout):
            finished.add(future)
            emit(future.result())
    except FuturesTimeout:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    for future, module in futures.items():
        if future not in finished:
            emit(CheckResult(module.ID, module.CATEGORY, "error", message=f"timed out after {timeout:g}s"))

    ctx.client.close()
    results.sort(key=lambda r: r.check_id)
    return ScanReport(
        target=ctx.target.url,
        started=started,
        finished=datetime.now(timezone.utc),
        version=__version__,
        options={"ports": bool(options.get("ports"))},
        results=results,
    )
```

- [ ] **Step 5: Run to verify it passes, then commit**

Run: `pytest tests/test_runner.py -v`
Expected: all PASS

```bash
git add siteward/core/context.py siteward/core/runner.py tests/conftest.py tests/test_runner.py
git commit -m "feat(core): scan context and concurrent runner" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Checks A — headers, cookies, CORS, leakage, HTTPS redirect, policy files

**Files:**
- Create: `siteward/checks/headers.py`, `cookies.py`, `cors.py`, `leakage.py`, `redirect_https.py`, `policy_files.py`
- Test: `tests/test_check_headers.py`, `test_check_cookies.py`, `test_check_cors.py`, `test_check_leakage.py`, `test_check_redirect_https.py`, `test_check_policy_files.py`

**Interfaces:**
- Consumes: `ScanContext` (`ctx.target`, `ctx.client.get(url, follow=True, headers=None) -> Fetch`, `ctx.baseline`), `Finding`.
- Produces: six check modules each with `ID`, `CATEGORY`, `OPT_IN = None`, `run(ctx) -> list[Finding]`. Finding ids produced: `headers.csp`, `headers.csp-weak`, `headers.hsts`, `headers.hsts-weak`, `headers.nosniff`, `headers.framing`, `headers.referrer`, `headers.permissions`; `cookies.secure`, `cookies.httponly`, `cookies.samesite`; `cors.reflected-origin`, `cors.null-origin`, `cors.wildcard`; `leakage.server-version`, `leakage.x-powered-by`, `leakage.verbose-errors`; `transport.no-https-redirect`; `policy.no-security-txt`, `policy.robots-sensitive`.

- [ ] **Step 1: Write the failing tests**

`tests/test_check_headers.py`:
```python
from siteward.checks import headers

GOOD = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "geolocation=()"),
]


def ids(findings):
    return {f.id for f in findings}


def test_good_headers_have_no_findings(server, ctx_for):
    server.add("/", "<html></html>", headers=GOOD)
    assert headers.run(ctx_for(server)) == []


def test_missing_headers_are_reported(server, ctx_for):
    assert ids(headers.run(ctx_for(server))) >= {
        "headers.csp", "headers.nosniff", "headers.framing", "headers.referrer", "headers.permissions"
    }


def test_hsts_is_only_expected_on_https(server, ctx_for):
    assert "headers.hsts" not in ids(headers.run(ctx_for(server)))  # fake server is plain http


def test_weak_csp_is_flagged_with_evidence(server, ctx_for):
    weak = [("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")] + GOOD[1:]
    server.add("/", "<html></html>", headers=weak)
    found = headers.run(ctx_for(server))
    assert ids(found) == {"headers.csp-weak"}
    assert "unsafe-inline" in found[0].evidence
```

`tests/test_check_cookies.py`:
```python
from siteward.checks import cookies


def test_session_cookie_without_flags(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "sessionid=SECRET123; Path=/")])
    found = cookies.run(ctx_for(server))
    by_id = {f.id: f for f in found}
    assert by_id["cookies.httponly"].severity == "medium"  # session-looking name
    assert "cookies.samesite" in by_id
    assert "cookies.secure" not in by_id  # plain-http target: Secure not expected
    assert all("SECRET123" not in f.evidence for f in found)  # never echo cookie values


def test_well_configured_cookie_is_clean(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "pref=1; Secure; HttpOnly; SameSite=Lax")])
    assert cookies.run(ctx_for(server)) == []


def test_samesite_none_requires_secure(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "a=1; HttpOnly; SameSite=None")])
    assert any(f.id == "cookies.secure" and f.severity == "medium" for f in cookies.run(ctx_for(server)))


def test_no_cookies_no_findings(server, ctx_for):
    assert cookies.run(ctx_for(server)) == []
```

`tests/test_check_cors.py`:
```python
from siteward.checks import cors


def test_reflected_origin_with_credentials_is_high(server, ctx_for):
    server.add("/", "<html></html>", headers=[
        ("Access-Control-Allow-Origin", cors.PROBE_ORIGIN), ("Access-Control-Allow-Credentials", "true")])
    found = cors.run(ctx_for(server))
    assert [(f.id, f.severity) for f in found] == [("cors.reflected-origin", "high")]


def test_reflected_origin_without_credentials_is_medium(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Access-Control-Allow-Origin", cors.PROBE_ORIGIN)])
    assert [(f.id, f.severity) for f in cors.run(ctx_for(server))] == [("cors.reflected-origin", "medium")]


def test_wildcard_is_informational(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Access-Control-Allow-Origin", "*")])
    assert [(f.id, f.severity) for f in cors.run(ctx_for(server))] == [("cors.wildcard", "info")]


def test_no_cors_headers_is_clean(server, ctx_for):
    assert cors.run(ctx_for(server)) == []


def test_probe_sends_origin_header(server, ctx_for):
    cors.run(ctx_for(server))
    assert any(h.get("Origin") == cors.PROBE_ORIGIN for _, _, h in server.requests)
```

`tests/test_check_leakage.py`:
```python
from siteward.checks import leakage


def ids(findings):
    return {f.id for f in findings}


def test_clean_server(server, ctx_for):
    assert leakage.run(ctx_for(server)) == []


def test_server_version_and_powered_by(server, ctx_for):
    server.banner = "Apache/2.4.41"
    server.add("/", "<html></html>", headers=[("X-Powered-By", "PHP/7.4.3")])
    found = leakage.run(ctx_for(server))
    assert ids(found) == {"leakage.server-version", "leakage.x-powered-by"}
    assert any("Apache/2.4.41" in f.evidence for f in found)


def test_verbose_error_page(server, ctx_for):
    server.add(leakage.PROBE_PATH, "Traceback (most recent call last):\n  File x", status=500)
    assert ids(leakage.run(ctx_for(server))) == {"leakage.verbose-errors"}
```

`tests/test_check_redirect_https.py` (an https redirect cannot be served by the local http fake server, so the passing cases use a stub client):
```python
from types import SimpleNamespace as NS

import httpx

from siteward.checks import redirect_https
from siteward.core.netguard import Fetch, FetchError


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
```

`tests/test_check_policy_files.py`:
```python
from siteward.checks import policy_files


def ids(findings):
    return {f.id for f in findings}


def test_missing_security_txt_is_informational(server, ctx_for):
    found = policy_files.run(ctx_for(server))
    assert ids(found) == {"policy.no-security-txt"} and found[0].severity == "info"


def test_valid_security_txt_passes(server, ctx_for):
    server.add("/.well-known/security.txt", "Contact: mailto:security@example.com\n")
    assert policy_files.run(ctx_for(server)) == []


def test_soft_404_site_does_not_fake_a_security_txt(server, ctx_for):
    server.set_default("<html>home</html>", headers=[("Content-Type", "text/html")])
    assert ids(policy_files.run(ctx_for(server))) == {"policy.no-security-txt"}  # no "Contact:" -> still missing


def test_robots_listing_sensitive_paths(server, ctx_for):
    server.add("/.well-known/security.txt", "Contact: mailto:a@b.co\n")
    server.add("/robots.txt", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /blog/\n")
    found = policy_files.run(ctx_for(server))
    assert ids(found) == {"policy.robots-sensitive"}
    assert "/admin/" in found[0].evidence and "/blog/" not in found[0].evidence
```

- [ ] **Step 2: Run to verify they fail**

Run: `pytest tests/test_check_headers.py tests/test_check_cookies.py tests/test_check_cors.py tests/test_check_leakage.py tests/test_check_redirect_https.py tests/test_check_policy_files.py -v`
Expected: FAIL with `ImportError` for `siteward.checks.*`

- [ ] **Step 3: Implement the six checks**

`siteward/checks/headers.py`:
```python
import re

from siteward.core.models import Finding

ID = "headers.security"
CATEGORY = "Headers"
OPT_IN = None


def run(ctx):
    h = ctx.baseline.headers
    out = []

    def add(slug, title, severity, fix, evidence="header not present"):
        out.append(Finding(f"headers.{slug}", title, CATEGORY, severity, evidence, fix))

    csp = h.get("content-security-policy")
    if not csp:
        add("csp", "Content-Security-Policy header missing", "medium",
            "Add a Content-Security-Policy that restricts script and frame sources.")
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        add("csp-weak", "Content-Security-Policy allows unsafe-inline/unsafe-eval", "low",
            "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes.", evidence=csp)

    hsts = h.get("strict-transport-security")
    if ctx.target.scheme == "https":
        if not hsts:
            add("hsts", "Strict-Transport-Security header missing", "medium",
                "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
        else:
            match = re.search(r"max-age=(\d+)", hsts, re.I)
            if not match or int(match.group(1)) < 15552000:
                add("hsts-weak", "HSTS max-age is shorter than 180 days", "low",
                    "Use a max-age of at least 15552000 (180 days).", evidence=hsts)

    if (h.get("x-content-type-options") or "").lower() != "nosniff":
        add("nosniff", "X-Content-Type-Options: nosniff missing", "low",
            "Send 'X-Content-Type-Options: nosniff'.")

    if not h.get("x-frame-options") and "frame-ancestors" not in (csp or ""):
        add("framing", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "medium",
            "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.")

    if not h.get("referrer-policy"):
        add("referrer", "Referrer-Policy header missing", "low",
            "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).")

    if not h.get("permissions-policy"):
        add("permissions", "Permissions-Policy header missing", "info",
            "Send a Permissions-Policy disabling features the site does not use.")
    return out
```

`siteward/checks/cookies.py`:
```python
import re

from siteward.core.models import Finding

ID = "cookies.flags"
CATEGORY = "Cookies"
OPT_IN = None
_SENSITIVE = re.compile(r"sess|token|auth|jwt|sid|login", re.I)


def run(ctx):
    https = ctx.target.scheme == "https"
    out = []
    for raw in ctx.baseline.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = next((a.split("=", 1)[1] for a in attrs if a.startswith("samesite=")), None)
        evidence = f"cookie '{name}' attributes: {'; '.join(attrs) or 'none'}"

        def add(slug, title, severity, fix):
            out.append(Finding(f"cookies.{slug}", f"{title} ({name})", CATEGORY, severity, evidence, fix))

        if https and not secure:
            add("secure", "Cookie missing Secure flag", "medium", "Set the Secure attribute.")
        if not httponly:
            severity = "medium" if _SENSITIVE.search(name) else "low"
            add("httponly", "Cookie missing HttpOnly flag", severity, "Set the HttpOnly attribute.")
        if samesite is None:
            add("samesite", "Cookie missing SameSite attribute", "low", "Set SameSite=Lax (or Strict).")
        elif samesite == "none" and not secure:
            add("secure", "SameSite=None cookie without Secure", "medium", "SameSite=None requires Secure.")
    return out
```

`siteward/checks/cors.py`:
```python
from siteward.core.models import Finding

ID = "cors.policy"
CATEGORY = "CORS"
OPT_IN = None
PROBE_ORIGIN = "https://siteward-cors-probe.example"


def run(ctx):
    fetch = ctx.client.get(ctx.target.url, headers={"Origin": PROBE_ORIGIN})
    allow = fetch.headers.get("access-control-allow-origin")
    credentials = (fetch.headers.get("access-control-allow-credentials") or "").lower() == "true"
    evidence = f"Access-Control-Allow-Origin: {allow}; Allow-Credentials: {credentials}"
    if allow == PROBE_ORIGIN:
        severity = "high" if credentials else "medium"
        return [Finding("cors.reflected-origin", "CORS reflects arbitrary Origin", CATEGORY, severity, evidence,
                        "Allow only an explicit list of trusted origins.")]
    if allow == "null" and credentials:
        return [Finding("cors.null-origin", "CORS allows the 'null' origin with credentials", CATEGORY, "high",
                        evidence, "Never allow the null origin with credentials.")]
    if allow == "*":
        return [Finding("cors.wildcard", "CORS allows any origin (*)", CATEGORY, "info", evidence,
                        "Fine for public static content; restrict it if the responses are sensitive.")]
    return []
```

`siteward/checks/leakage.py`:
```python
import re

from siteward.core.models import Finding

ID = "leakage.banner"
CATEGORY = "Information leakage"
OPT_IN = None
PROBE_PATH = "/siteward-not-found-probe"
_VERSIONED = re.compile(r"\d+\.\d+")
_TRACE_MARKERS = ("Traceback (most recent call last)", "Stack trace:", "at java.", "Fatal error:", "SQLSTATE", "Whoops!")


def run(ctx):
    h = ctx.baseline.headers
    out = []
    server = h.get("server", "")
    if _VERSIONED.search(server):
        out.append(Finding("leakage.server-version", "Server header discloses software version", CATEGORY, "low",
                           f"Server: {server}", "Configure the server to hide its version."))
    for name in ("x-powered-by", "x-aspnet-version", "x-generator"):
        if h.get(name):
            out.append(Finding("leakage.x-powered-by", f"{name} header discloses technology", CATEGORY, "low",
                               f"{name}: {h.get(name)}", f"Remove the {name} header."))
    probe = ctx.client.get(ctx.target.url.rstrip("/") + PROBE_PATH)
    if any(marker in probe.text for marker in _TRACE_MARKERS):
        out.append(Finding("leakage.verbose-errors", "Error page exposes a stack trace", CATEGORY, "medium",
                           f"GET {PROBE_PATH} -> {probe.status} with debug output",
                           "Disable debug/verbose error output in production."))
    return out
```

`siteward/checks/redirect_https.py`:
```python
from siteward.core.models import Finding
from siteward.core.netguard import FetchError

ID = "transport.https-redirect"
CATEGORY = "Transport"
OPT_IN = None


def run(ctx):
    t = ctx.target
    if t.scheme == "https":
        host = f"[{t.host}]" if ":" in t.host else t.host
        url = f"http://{host}/"
    else:
        url = t.url
    try:
        fetch = ctx.client.get(url, follow=False)
    except FetchError:
        return []  # nothing answers on plain HTTP
    location = fetch.headers.get("location", "")
    if fetch.status in (301, 302, 303, 307, 308) and location.lower().startswith("https://"):
        return []
    return [Finding("transport.no-https-redirect", "HTTP does not redirect to HTTPS", CATEGORY, "medium",
                    f"GET {url} -> {fetch.status}", "Redirect all HTTP requests to HTTPS (301).")]
```

`siteward/checks/policy_files.py`:
```python
import re

from siteward.core.models import Finding

ID = "policy.files"
CATEGORY = "Policy files"
OPT_IN = None
_SENSITIVE = re.compile(r"admin|backup|private|secret|internal|\.git|config|staging|test", re.I)


def run(ctx):
    base = ctx.target.url.rstrip("/")
    out = []

    has_security_txt = False
    for path in ("/.well-known/security.txt", "/security.txt"):
        fetch = ctx.client.get(base + path)
        if fetch.status == 200 and "contact:" in fetch.text.lower():  # "Contact:" guards against soft-404 pages
            has_security_txt = True
            break
    if not has_security_txt:
        out.append(Finding("policy.no-security-txt", "No security.txt published (RFC 9116)", CATEGORY, "info",
                           "/.well-known/security.txt not found",
                           "Publish a security.txt with a Contact so researchers can report issues."))

    robots = ctx.client.get(base + "/robots.txt")
    if robots.status == 200:
        paths = [m.group(1).strip() for m in re.finditer(r"(?im)^disallow:\s*(\S+)", robots.text)]
        sensitive = [p for p in paths if _SENSITIVE.search(p)]
        if sensitive:
            out.append(Finding("policy.robots-sensitive", "robots.txt lists potentially sensitive paths", CATEGORY,
                               "info", ", ".join(sensitive[:10]),
                               "robots.txt is public; do not rely on it to hide paths, and secure them properly."))
    return out
```

- [ ] **Step 4: Run to verify they pass**

Run: `pytest tests/test_check_headers.py tests/test_check_cookies.py tests/test_check_cors.py tests/test_check_leakage.py tests/test_check_redirect_https.py tests/test_check_policy_files.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add siteward/checks tests/test_check_*.py
git commit -m "feat(checks): headers, cookies, CORS, leakage, HTTPS redirect, policy files" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Checks B — exposure, TLS, DNS email, takeover, ports

**Files:**
- Create: `siteward/checks/exposure.py`, `tls.py`, `dns_email.py`, `takeover.py`, `ports.py`
- Test: `tests/test_check_exposure.py`, `test_check_tls.py`, `test_check_dns_email.py`, `test_check_takeover.py`, `test_check_ports.py`

**Interfaces:**
- Consumes: `ScanContext`, `Finding`, `Skip`, `FetchError`.
- Produces: five check modules (same module contract as Task 5). `ports.py` has `OPT_IN = "ports"` and `PORTS: dict[int, tuple[str, str]]` (port → (service name, severity)). Pure helpers used by tests: `tls._assess_cert(cert: dict, now: float) -> list[Finding]`, `dns_email.assess(spf: list[str], dmarc: list[str], dkim_found: bool) -> list[Finding]`, `dns_email._txt(name) -> list[str]`, `takeover._cname(name) -> str | None`, `takeover._exists(name) -> bool`.

- [ ] **Step 1: Write the failing tests**

`tests/test_check_exposure.py`:
```python
from siteward.checks import exposure


def ids(findings):
    return {f.id for f in findings}


def test_clean_site_has_no_findings(server, ctx_for):
    assert exposure.run(ctx_for(server)) == []


def test_soft_404_site_does_not_produce_false_positives(server, ctx_for):
    server.set_default("<html><body>Welcome home</body></html>", headers=[("Content-Type", "text/html")])
    assert exposure.run(ctx_for(server)) == []


def test_exposed_git_and_env_are_found_without_leaking_secrets(server, ctx_for):
    server.add("/.git/HEAD", "ref: refs/heads/main\n")
    server.add("/.env", "DB_PASSWORD=hunter2\nAPI_KEY=abc123\n")
    found = exposure.run(ctx_for(server))
    assert ids(found) == {"exposure.git", "exposure.env"}
    assert all(f.severity == "high" for f in found)
    blob = " ".join(f.evidence + f.title + f.remediation for f in found)
    assert "hunter2" not in blob and "abc123" not in blob


def test_sql_dump_and_phpinfo(server, ctx_for):
    server.add("/backup.sql", "CREATE TABLE users (id int);")
    server.add("/phpinfo.php", "<title>phpinfo()</title>")
    assert ids(exposure.run(ctx_for(server))) == {"exposure.sql-dump", "exposure.phpinfo"}


def test_directory_listing_on_homepage(server, ctx_for):
    server.add("/", "<html><title>Index of /</title></html>", headers=[("Content-Type", "text/html")])
    assert "exposure.directory-listing" in ids(exposure.run(ctx_for(server)))
```

`tests/test_check_tls.py`:
```python
import ssl
from types import SimpleNamespace as NS

import pytest

from siteward.checks import tls
from siteward.core.models import Skip


def at(text):
    return ssl.cert_time_to_seconds(text)


NOW = at("Jun  1 2029 00:00:00 GMT")


def test_healthy_cert_has_no_findings():
    assert tls._assess_cert({"notAfter": "Jan  1 00:00:00 2030 GMT"}, NOW) == []


def test_expiring_soon_is_high():
    found = tls._assess_cert({"notAfter": "Jun 10 00:00:00 2029 GMT"}, NOW)
    assert [(f.id, f.severity) for f in found] == [("tls.cert-expiring", "high")]


def test_expiring_within_30_days_is_medium():
    found = tls._assess_cert({"notAfter": "Jun 25 00:00:00 2029 GMT"}, NOW)
    assert [(f.id, f.severity) for f in found] == [("tls.cert-expiring", "medium")]


def test_expired_cert_is_high():
    found = tls._assess_cert({"notAfter": "May  1 00:00:00 2029 GMT"}, NOW)
    assert [(f.id, f.severity) for f in found] == [("tls.cert-expired", "high")]


def test_non_https_target_is_skipped():
    with pytest.raises(Skip):
        tls.run(NS(target=NS(scheme="http", host="x", port=80)))
```

`tests/test_check_dns_email.py`:
```python
from types import SimpleNamespace as NS

import pytest

from siteward.checks import dns_email
from siteward.core.models import Skip


def ids(findings):
    return {f.id for f in findings}


def test_well_configured_domain():
    spf = ["v=spf1 include:_spf.google.com -all"]
    dmarc = ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
    assert dns_email.assess(spf, dmarc, dkim_found=True) == []


def test_nothing_configured():
    found = dns_email.assess([], [], dkim_found=False)
    assert {"dns.no-spf", "dns.no-dmarc", "dns.dkim-not-found"} <= ids(found)


def test_permissive_spf_and_monitor_only_dmarc():
    found = dns_email.assess(["v=spf1 +all"], ["v=DMARC1; p=none"], dkim_found=True)
    assert ids(found) == {"dns.spf-permissive", "dns.dmarc-none"}


def test_multiple_spf_records_are_invalid():
    found = dns_email.assess(["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=reject"], dkim_found=True)
    assert ids(found) == {"dns.spf-multiple"}


def test_run_uses_dns_lookups(monkeypatch):
    answers = {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]}
    monkeypatch.setattr(dns_email, "_txt", lambda name: answers.get(name, []))
    assert dns_email.run(NS(target=NS(host="example.com"))) == []


def test_ip_targets_are_skipped():
    with pytest.raises(Skip):
        dns_email.run(NS(target=NS(host="93.184.216.34")))
```

`tests/test_check_takeover.py`:
```python
from types import SimpleNamespace as NS

import pytest

from siteward.checks import takeover
from siteward.core.models import Skip


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
```

`tests/test_check_ports.py`:
```python
import socket

from siteward.checks import ports


def test_open_port_is_reported_and_closed_is_not(server, ctx_for, monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    open_port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    monkeypatch.setattr(ports, "PORTS", {open_port: ("TestDB", "high"), closed_port: ("Nothing", "high")})
    try:
        found = ports.run(ctx_for(server, ports=True))
    finally:
        listener.close()
    assert [(f.id, f.severity) for f in found] == [("ports.open", "high")]
    assert f"{open_port}/tcp" in found[0].evidence and "TestDB" in found[0].evidence


def test_check_is_opt_in():
    assert ports.OPT_IN == "ports"
    assert 22 in ports.PORTS and 3306 in ports.PORTS and 3389 in ports.PORTS
```

- [ ] **Step 2: Run to verify they fail**

Run: `pytest tests/test_check_exposure.py tests/test_check_tls.py tests/test_check_dns_email.py tests/test_check_takeover.py tests/test_check_ports.py -v`
Expected: FAIL with `ImportError` for the new modules

- [ ] **Step 3: Implement the five checks**

`siteward/checks/exposure.py`:
```python
import re

from siteward.core.models import Finding
from siteward.core.netguard import FetchError

ID = "exposure.files"
CATEGORY = "Exposed files"
OPT_IN = None


def _git(body):
    return body.startswith(b"ref:") or b"[core]" in body


def _env(body):
    return re.search(rb"^[A-Z][A-Z0-9_]*=.+$", body, re.M) is not None


def _sql(body):
    return b"CREATE TABLE" in body or b"INSERT INTO" in body


def _zip(body):
    return body.startswith(b"PK\x03\x04")


# (path, slug, validator, severity, title, fix). Validators look at CONTENT, so a site that
# answers 200 to every path (soft 404) produces no false positives.
PROBES = [
    ("/.git/HEAD", "git", _git, "high", "Git repository is publicly accessible",
     "Block access to /.git and remove it from the web root."),
    ("/.git/config", "git", _git, "high", "Git repository is publicly accessible",
     "Block access to /.git and remove it from the web root."),
    ("/.env", "env", _env, "high", "Environment file (.env) is publicly accessible",
     "Remove .env from the web root and rotate any secrets it contained."),
    ("/wp-config.php.bak", "config-backup", lambda b: b"DB_PASSWORD" in b, "high",
     "Configuration backup is publicly accessible", "Delete backup files from the web root and rotate credentials."),
    ("/config.php.bak", "config-backup", lambda b: b"<?php" in b, "high",
     "Configuration backup is publicly accessible", "Delete backup files from the web root and rotate credentials."),
    ("/backup.sql", "sql-dump", _sql, "high", "Database dump is publicly accessible",
     "Remove database dumps from the web root."),
    ("/dump.sql", "sql-dump", _sql, "high", "Database dump is publicly accessible",
     "Remove database dumps from the web root."),
    ("/backup.zip", "archive", _zip, "high", "Backup archive is publicly accessible",
     "Remove archives from the web root."),
    ("/.DS_Store", "ds-store", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"), "low",
     ".DS_Store file reveals directory contents", "Delete .DS_Store files from deployments."),
    ("/phpinfo.php", "phpinfo", lambda b: b"phpinfo()" in b, "medium", "phpinfo() page is publicly accessible",
     "Remove phpinfo pages from production."),
    ("/server-status", "server-status", lambda b: b"Apache Server Status" in b, "medium",
     "Apache server-status page is publicly accessible", "Restrict /server-status to localhost."),
]
_LISTING_DIRS = ("/uploads/", "/backup/", "/files/")


def run(ctx):
    base = ctx.target.url.rstrip("/")
    out, seen = [], set()
    for path, slug, valid, severity, title, fix in PROBES:
        if slug in seen:
            continue
        try:
            fetch = ctx.client.get(base + path)
        except FetchError:
            continue
        if fetch.status == 200 and valid(fetch.body):
            seen.add(slug)
            # Evidence names the path only; file contents (secrets) are never copied into the report.
            out.append(Finding(f"exposure.{slug}", title, CATEGORY, severity,
                               f"GET {path} returned 200 ({len(fetch.body)} bytes); content not reproduced", fix))

    pages = [("/", ctx.baseline)]
    for directory in _LISTING_DIRS:
        try:
            pages.append((directory, ctx.client.get(base + directory)))
        except FetchError:
            continue
    for path, fetch in pages:
        if fetch.status == 200 and re.search(r"<title>\s*Index of /", fetch.text, re.I):
            out.append(Finding("exposure.directory-listing", "Directory listing is enabled", CATEGORY, "medium",
                               f"{path} shows an 'Index of' page", "Disable directory listing (autoindex off)."))
            break
    return out
```

`siteward/checks/tls.py`:
```python
import socket
import ssl
import time

from siteward.core.models import Finding, Skip

ID = "tls.certificate"
CATEGORY = "TLS"
OPT_IN = None
TIMEOUT = 8.0


def _assess_cert(cert: dict, now: float) -> list:
    days = (ssl.cert_time_to_seconds(cert["notAfter"]) - now) / 86400
    if days < 0:
        return [Finding("tls.cert-expired", "TLS certificate has expired", CATEGORY, "high",
                        f"notAfter: {cert['notAfter']}", "Renew the certificate immediately.")]
    if days < 30:
        severity = "high" if days < 14 else "medium"
        return [Finding("tls.cert-expiring", f"TLS certificate expires in {int(days)} days", CATEGORY, severity,
                        f"notAfter: {cert['notAfter']}", "Renew the certificate and enable auto-renewal.")]
    return []


def _fetch_cert(host, port):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version()


def _accepts_legacy(host, port):
    """Return the negotiated version if TLS 1.0/1.1 is accepted, False if refused, None if we cannot test."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Certificate verification is deliberately off HERE ONLY: this is a protocol-support probe that
    # sends no data and trusts nothing it receives. The real certificate check is _fetch_cert above.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None
    try:
        with socket.create_connection((host, port), TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.version()
    except (ssl.SSLError, OSError):
        return False


def run(ctx):
    t = ctx.target
    if t.scheme != "https":
        raise Skip("target is not served over HTTPS")
    try:
        cert, version = _fetch_cert(t.host, t.port)
    except ssl.SSLCertVerificationError as exc:
        return [Finding("tls.cert-invalid", "TLS certificate failed verification", CATEGORY, "high",
                        exc.verify_message or str(exc), "Install a valid certificate from a trusted CA that matches the hostname.")]
    except ssl.SSLError as exc:
        return [Finding("tls.handshake-failed", "TLS handshake failed", CATEGORY, "high", str(exc),
                        "Check the server's TLS configuration.")]
    out = _assess_cert(cert, time.time())
    if version in ("TLSv1", "TLSv1.1"):
        out.append(Finding("tls.legacy-protocol", f"Negotiated legacy protocol {version}", CATEGORY, "high",
                           version, "Disable TLS 1.0/1.1; require TLS 1.2+."))
    elif _accepts_legacy(t.host, t.port):
        out.append(Finding("tls.legacy-protocol", "Server accepts TLS 1.0/1.1", CATEGORY, "medium",
                           "A TLS 1.0/1.1 handshake succeeded", "Disable TLS 1.0/1.1; require TLS 1.2+."))
    return out
```

`siteward/checks/dns_email.py`:
```python
import ipaddress
import re

import dns.exception
import dns.resolver

from siteward.core.models import Finding, Skip

ID = "dns.email"
CATEGORY = "DNS / Email"
OPT_IN = None
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail")


def _txt(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except dns.exception.DNSException:
        return []
    return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in answers]


def assess(spf, dmarc, dkim_found):
    out = []

    def add(slug, title, severity, evidence, fix):
        out.append(Finding(f"dns.{slug}", title, CATEGORY, severity, evidence, fix))

    if not spf:
        add("no-spf", "No SPF record", "medium", "no TXT record starting with v=spf1",
            "Publish an SPF record, e.g. 'v=spf1 -all' if the domain sends no mail.")
    elif len(spf) > 1:
        add("spf-multiple", "Multiple SPF records (invalid)", "medium", " | ".join(spf), "Merge into a single SPF record.")
    elif "+all" in spf[0] or "?all" in spf[0]:
        add("spf-permissive", "SPF allows any sender", "high" if "+all" in spf[0] else "low", spf[0],
            "End the SPF record with '-all' (or '~all').")

    if not dmarc:
        add("no-dmarc", "No DMARC record", "medium", "no TXT record at _dmarc", "Publish a DMARC record with p=quarantine or p=reject.")
    else:
        match = re.search(r"\bp=(\w+)", dmarc[0])
        if match and match.group(1).lower() == "none":
            add("dmarc-none", "DMARC policy is monitor-only (p=none)", "low", dmarc[0],
                "Move to p=quarantine or p=reject once reports look clean.")

    if not dkim_found:
        add("dkim-not-found", "No DKIM key found on common selectors", "info",
            f"checked: {', '.join(DKIM_SELECTORS)}",
            "Informational: DKIM selectors cannot be enumerated. Ignore if your mail provider uses a custom selector.")
    return out


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _candidates(host):
    host = host.removeprefix("www.")
    labels = host.split(".")
    return [host] + ([".".join(labels[1:])] if len(labels) > 2 else [])


def run(ctx):
    host = ctx.target.host
    if _is_ip(host):
        raise Skip("target is an IP address; no mail DNS to check")
    domain = _candidates(host)[0]
    spf = dmarc = []
    for candidate in _candidates(host):
        spf = [r for r in _txt(candidate) if r.lower().startswith("v=spf1")]
        dmarc = [r for r in _txt(f"_dmarc.{candidate}") if r.lower().startswith("v=dmarc1")]
        if spf or dmarc:
            domain = candidate
            break
    dkim_found = any(_txt(f"{sel}._domainkey.{domain}") for sel in DKIM_SELECTORS)
    return assess(spf, dmarc, dkim_found)
```

`siteward/checks/takeover.py`:
```python
import ipaddress

import dns.exception
import dns.resolver

from siteward.core.models import Finding, Skip

ID = "dns.takeover"
CATEGORY = "DNS / Email"
OPT_IN = None

# CNAME suffix -> text shown by the provider for an unclaimed resource
PROVIDERS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "Web app not found",
    "surge.sh": "project not found",
}


def _cname(name):
    try:
        answers = dns.resolver.resolve(name, "CNAME", lifetime=5)
    except dns.exception.DNSException:
        return None
    return str(answers[0].target).rstrip(".").lower()


def _exists(name):
    try:
        dns.resolver.resolve(name, "A", lifetime=5)
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.DNSException:
        return True  # unsure: do not raise a false alarm
    return True


def run(ctx):
    host = ctx.target.host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise Skip("target is an IP address")
    target = _cname(host)
    if not target:
        return []
    if not _exists(target):
        return [Finding("takeover.dangling-cname", "CNAME points at a name that does not resolve", CATEGORY, "high",
                        f"{host} -> {target} (NXDOMAIN)",
                        "Remove the stale CNAME or re-claim the target resource.")]
    for suffix, fingerprint in PROVIDERS.items():
        if target.endswith(suffix) and fingerprint in ctx.baseline.text:
            return [Finding("takeover.unclaimed-service", "CNAME points at an unclaimed third-party resource",
                            CATEGORY, "high", f"{host} -> {target}; provider 'not found' page served",
                            "Re-claim the resource or remove the DNS record.")]
    return []
```

`siteward/checks/ports.py`:
```python
import socket
from concurrent.futures import ThreadPoolExecutor

from siteward.core.models import Finding

ID = "ports.common"
CATEGORY = "Network"
OPT_IN = "ports"
TIMEOUT = 1.5

# port -> (service, severity if reachable from the internet)
PORTS = {
    21: ("FTP", "high"), 22: ("SSH", "info"), 23: ("Telnet", "high"), 25: ("SMTP", "low"), 53: ("DNS", "info"),
    110: ("POP3", "low"), 135: ("MS RPC", "high"), 139: ("NetBIOS", "high"), 143: ("IMAP", "low"),
    445: ("SMB", "high"), 1433: ("MS SQL", "high"), 1521: ("Oracle DB", "high"), 3306: ("MySQL", "high"),
    3389: ("RDP", "high"), 5432: ("PostgreSQL", "high"), 5900: ("VNC", "high"), 6379: ("Redis", "high"),
    8080: ("HTTP alt", "info"), 9200: ("Elasticsearch", "high"), 11211: ("Memcached", "high"),
    27017: ("MongoDB", "high"),
}


def _is_open(ip, port):
    try:
        with socket.create_connection((ip, port), TIMEOUT):
            return True
    except OSError:
        return False


def run(ctx):
    ip = ctx.target.ips[0]  # an address netguard already approved
    ports = sorted(PORTS)
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(lambda p: _is_open(ip, p), ports))
    out = []
    for port, is_open in zip(ports, states):
        if is_open:
            name, severity = PORTS[port]
            out.append(Finding("ports.open", f"{name} port {port} is reachable", CATEGORY, severity,
                               f"{port}/tcp open ({name})",
                               "Close the port or restrict it with a firewall to trusted addresses."))
    return out
```

- [ ] **Step 4: Run to verify they pass**

Run: `pytest tests/test_check_exposure.py tests/test_check_tls.py tests/test_check_dns_email.py tests/test_check_takeover.py tests/test_check_ports.py -v`
Expected: all PASS

- [ ] **Step 5: Add a discovery test and commit**

Append to `tests/test_runner.py`:
```python
def test_all_builtin_checks_are_discovered():
    from siteward.core.runner import discover_checks

    ids = {m.ID for m in discover_checks()}
    assert ids >= {
        "headers.security", "cookies.flags", "cors.policy", "leakage.banner", "transport.https-redirect",
        "policy.files", "exposure.files", "tls.certificate", "dns.email", "dns.takeover", "ports.common",
    }
```
Run: `pytest -q` — Expected: all PASS.

```bash
git add siteward/checks tests
git commit -m "feat(checks): exposure, TLS, email DNS, takeover and opt-in port checks" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Report exporters (JSON, Markdown, HTML)

**Files:**
- Create: `siteward/reports/json_report.py`, `markdown_report.py`, `html_report.py`, `report.html.j2`
- Modify: `siteward/reports/__init__.py`, `tests/conftest.py` (add `sample_report`)
- Test: `tests/test_reports.py`

**Interfaces:**
- Consumes: `ScanReport.to_dict()`.
- Produces: `to_json(report) -> str`, `to_markdown(report) -> str`, `to_html(report) -> str` (self-contained, no external resources); `FORMATS: dict[str, tuple[callable, content_type, extension]]` keys `json|md|html`; `render(report, fmt) -> str`. Fixture `sample_report` (contains a hostile `<script>` string in a finding).

- [ ] **Step 1: Add the fixture and write the failing tests**

Append to `tests/conftest.py`:
```python
from datetime import datetime, timezone  # noqa: E402

from siteward.core.models import CheckResult, Finding, ScanReport  # noqa: E402

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
```

`tests/test_reports.py`:
```python
import json

import pytest

from siteward.reports import FORMATS, render, to_html, to_json, to_markdown


def test_json_roundtrips(sample_report):
    data = json.loads(to_json(sample_report))
    assert data["target"] == "http://example.com/" and data["grade"] == "C" and data["incomplete"] is True


def test_markdown_lists_findings_passed_skipped_and_errors(sample_report):
    md = to_markdown(sample_report)
    assert md.startswith("# Security scan")
    assert "CSP missing" in md and "Add a CSP" in md
    assert "cookies.flags" in md  # passed check is listed
    assert "target is not served over HTTPS" in md  # skipped reason
    assert "TimeoutError: lookup" in md  # errored check is never hidden


def test_markdown_neutralises_hostile_content(sample_report):
    md = to_markdown(sample_report)
    # the title is outside a code fence, so markup characters must be backslash-escaped
    assert "X-Powered-By: \\<script\\>alert(1)\\</script\\>" in md
    # evidence containing a ``` run must be fenced with a longer fence so it cannot break out
    assert "````" in md


def test_html_escapes_hostile_content(sample_report):
    html = to_html(sample_report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_is_self_contained(sample_report):
    html = to_html(sample_report)
    for banned in ("<link", "src=", "@import", "http://cdn", "https://cdn"):
        assert banned not in html
    assert "<style>" in html and "CSP missing" in html


def test_render_dispatch_and_formats(sample_report):
    assert set(FORMATS) == {"json", "md", "html"}
    assert render(sample_report, "json") == to_json(sample_report)
    with pytest.raises(KeyError):
        render(sample_report, "pdf")
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_reports.py -v`
Expected: FAIL with `ImportError: cannot import name 'FORMATS' from 'siteward.reports'`

- [ ] **Step 3: Implement**

`siteward/reports/json_report.py`:
```python
import json


def to_json(report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
```

`siteward/reports/markdown_report.py`:
```python
import re

from siteward.core.models import SEVERITIES

_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~])")


def _esc(text) -> str:
    """Escape target-controlled text used outside code fences."""
    return _SPECIAL.sub(r"\\\1", str(text).replace("\r", " ").replace("\n", " "))


def _fence(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    mark = "`" * max(3, longest + 1)
    return f"{mark}\n{text}\n{mark}"


def to_markdown(report) -> str:
    d = report.to_dict()
    lines = [
        f"# Security scan: {_esc(d['target'])}",
        "",
        f"- **Grade:** {d['grade']}" + (" (incomplete: some checks errored)" if d["incomplete"] else ""),
        f"- **Scanned:** {d['started']}",
        f"- **Tool:** siteward {d['version']} (port check: {'on' if d['options'].get('ports') else 'off'})",
        "- **Counts:** " + ", ".join(f"{s} {d['counts'][s]}" for s in reversed(SEVERITIES)),
        "",
        "## Findings",
        "",
    ]
    findings = report.findings
    if not findings:
        lines += ["No findings.", ""]
    for f in findings:
        lines += [f"### [{f.severity.upper()}] {_esc(f.title)}", ""]
        if f.evidence:
            lines += ["Evidence:", "", _fence(f.evidence), ""]
        if f.remediation:
            lines += [f"**Fix:** {_esc(f.remediation)}", ""]

    for heading, status in (("Errored checks", "error"), ("Skipped checks", "skipped"), ("Passed checks", "passed")):
        rows = [r for r in d["results"] if r["status"] == status]
        if rows:
            lines += [f"## {heading}", ""]
            for r in rows:
                extra = f": {_esc(r['message'])}" if r["message"] else ""
                lines.append(f"- `{r['check_id']}`{extra}")
            lines.append("")
    return "\n".join(lines)
```

`siteward/reports/html_report.py`:
```python
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from siteward.core.models import SEVERITIES

_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent)), autoescape=True)


def to_html(report) -> str:
    d = report.to_dict()
    template = _env.get_template("report.html.j2")
    return template.render(
        r=d,
        severities=list(reversed(SEVERITIES)),
        findings=report.findings,
        errors=[x for x in d["results"] if x["status"] == "error"],
        skipped=[x for x in d["results"] if x["status"] == "skipped"],
        passed=[x for x in d["results"] if x["status"] == "passed"],
    )
```

`siteward/reports/report.html.j2`:
```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security scan report</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; color: #1b1f24; }
  h1 { font-size: 1.5rem; } h2 { margin-top: 2rem; font-size: 1.15rem; }
  .meta { color: #57606a; }
  .grade { display: inline-block; font-weight: 700; font-size: 1.4rem; padding: .1rem .7rem; border-radius: .4rem; background: #eef1f4; }
  .counts span, .sev { display: inline-block; padding: 0 .5rem; border-radius: .3rem; font-size: .85rem; font-weight: 600; margin-right: .3rem; }
  .sev-critical, .sev-high { background: #ffd8d3; color: #8a1f11; }
  .sev-medium { background: #ffecb5; color: #6b4e00; }
  .sev-low { background: #d6ebff; color: #0b4a7d; }
  .sev-info { background: #e6e9ed; color: #3b434b; }
  details { border: 1px solid #d0d7de; border-radius: .4rem; padding: .6rem .8rem; margin: .5rem 0; }
  summary { cursor: pointer; font-weight: 600; }
  pre { background: #f6f8fa; padding: .6rem; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
  li code { background: #f6f8fa; padding: 0 .25rem; }
</style>
</head>
<body>
<h1>Security scan: {{ r.target }}</h1>
<p class="meta">Scanned {{ r.started }} &middot; siteward {{ r.version }} &middot; port check {{ 'on' if r.options.ports else 'off' }}</p>
<p>Grade <span class="grade">{{ r.grade }}</span>{% if r.incomplete %} <strong>(incomplete: some checks errored)</strong>{% endif %}</p>
<p class="counts">{% for s in severities %}<span class="sev-{{ s }}">{{ s }} {{ r.counts[s] }}</span>{% endfor %}</p>

<h2>Findings</h2>
{% if not findings %}<p>No findings.</p>{% endif %}
{% for f in findings %}
<details>
  <summary><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span>{{ f.title }}</summary>
  {% if f.evidence %}<p>Evidence:</p><pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.remediation %}<p><strong>Fix:</strong> {{ f.remediation }}</p>{% endif %}
</details>
{% endfor %}

{% if errors %}<h2>Errored checks</h2><ul>{% for x in errors %}<li><code>{{ x.check_id }}</code>: {{ x.message }}</li>{% endfor %}</ul>{% endif %}
{% if skipped %}<h2>Skipped checks</h2><ul>{% for x in skipped %}<li><code>{{ x.check_id }}</code>: {{ x.message }}</li>{% endfor %}</ul>{% endif %}
{% if passed %}<h2>Passed checks</h2><ul>{% for x in passed %}<li><code>{{ x.check_id }}</code></li>{% endfor %}</ul>{% endif %}
</body>
</html>
```

`siteward/reports/__init__.py`:
```python
from .html_report import to_html
from .json_report import to_json
from .markdown_report import to_markdown

FORMATS = {
    "json": (to_json, "application/json", "json"),
    "md": (to_markdown, "text/markdown; charset=utf-8", "md"),
    "html": (to_html, "text/html; charset=utf-8", "html"),
}


def render(report, fmt: str) -> str:
    return FORMATS[fmt][0](report)
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_reports.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add siteward/reports tests/conftest.py tests/test_reports.py
git commit -m "feat(reports): JSON, Markdown and self-contained HTML exporters" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8: CLI

**Files:**
- Create: `siteward/cli/main.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `run_scan`, `ScanError`, `BlockedTarget`, `render`, `FORMATS`, `severity_rank`, `SEVERITIES`.
- Produces: Typer app `siteward.cli.main:app`; command `siteward scan URL [--ports] [--format json|md|html] [--out FILE] [--fail-on LEVEL] [--allow-private]`. Exit codes: `0` ok, `1` findings at/above `--fail-on` (default `high`; `never` disables), `2` refused/unreachable/bad option. Progress and the authorisation notice go to stderr; the report goes to stdout or `--out`.

- [ ] **Step 1: Write the failing tests**

`tests/test_cli.py`:
```python
import json

from typer.testing import CliRunner

from siteward.cli.main import app

runner = CliRunner()


def scan(server, *args):
    return runner.invoke(app, ["scan", server.url, "--allow-private", *args])


def test_markdown_report_to_stdout_and_exit_zero_for_medium_findings(server):
    result = scan(server)
    assert result.exit_code == 0  # plain fake server: medium findings only, default --fail-on high
    assert "# Security scan" in result.stdout


def test_fail_on_medium_exits_one(server):
    assert scan(server, "--fail-on", "medium").exit_code == 1


def test_high_severity_finding_fails_by_default(server):
    server.add("/.env", "SECRET_KEY=abc\n")
    assert scan(server).exit_code == 1


def test_fail_on_never_always_exits_zero(server):
    server.add("/.env", "SECRET_KEY=abc\n")
    assert scan(server, "--fail-on", "never").exit_code == 0


def test_json_output_is_valid(server):
    result = scan(server, "--format", "json")
    assert json.loads(result.stdout)["target"].startswith("http://127.0.0.1")


def test_out_file_is_written(server, tmp_path):
    out = tmp_path / "report.html"
    result = scan(server, "--format", "html", "--out", str(out))
    assert result.exit_code == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_private_target_refused_without_flag(server):
    result = runner.invoke(app, ["scan", server.url])
    assert result.exit_code == 2 and "Refused" in result.output


def test_unreachable_target_exits_two():
    result = runner.invoke(app, ["scan", "http://127.0.0.1:1", "--allow-private"])
    assert result.exit_code == 2 and "Error" in result.output


def test_bad_format_and_bad_fail_on_exit_two(server):
    assert scan(server, "--format", "pdf").exit_code == 2
    assert scan(server, "--fail-on", "scary").exit_code == 2


def test_port_check_flag_enables_the_check(server):
    result = scan(server, "--ports", "--format", "json")
    data = json.loads(result.stdout)
    ports = next(r for r in data["results"] if r["check_id"] == "ports.common")
    assert ports["status"] != "skipped" and data["options"]["ports"] is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'siteward.cli.main'`

- [ ] **Step 3: Implement**

`siteward/cli/main.py`:
```python
from __future__ import annotations

from pathlib import Path

import typer

from siteward.core.models import SEVERITIES, severity_rank
from siteward.core.netguard import BlockedTarget
from siteward.core.runner import ScanError, run_scan
from siteward.reports import FORMATS, render

app = typer.Typer(add_completion=False, help="Passive web security scanner.")
NOTICE = "Only scan sites you own or are authorised to test."


@app.callback()
def main():
    """siteward: run passive security checks against a URL."""


def _err(message: str):
    typer.echo(message, err=True)


@app.command()
def scan(
    url: str = typer.Argument(..., help="Site to scan, e.g. https://example.com"),
    ports: bool = typer.Option(False, "--ports", help="Also run the opt-in TCP port check."),
    fmt: str = typer.Option("md", "--format", help="Report format: json, md or html."),
    out: Path | None = typer.Option(None, "--out", help="Write the report to this file instead of stdout."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if a finding is at/above: info|low|medium|high|critical|never."),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow private/loopback targets (local development only)."),
):
    if fmt not in FORMATS:
        _err(f"Error: --format must be one of {', '.join(FORMATS)}")
        raise typer.Exit(2)
    if fail_on != "never" and fail_on not in SEVERITIES:
        _err(f"Error: --fail-on must be one of {', '.join(SEVERITIES)}, never")
        raise typer.Exit(2)

    _err(NOTICE)
    try:
        report = run_scan(
            url,
            {"ports": ports, "allow_private": allow_private},
            on_result=lambda r: _err(f"  [{r.status:8}] {r.check_id}"),
        )
    except BlockedTarget as exc:
        _err(f"Refused: {exc}")
        raise typer.Exit(2)
    except ScanError as exc:
        _err(f"Error: {exc}")
        raise typer.Exit(2)

    text = render(report, fmt)
    if out:
        out.write_text(text, encoding="utf-8")
        _err(f"Report written to {out}")
    else:
        typer.echo(text)

    if fail_on != "never" and any(severity_rank(f.severity) >= severity_rank(fail_on) for f in report.findings):
        raise typer.Exit(1)
```

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_cli.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add siteward/cli/main.py tests/test_cli.py
git commit -m "feat(cli): siteward scan command with report formats and CI exit codes" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 9a: Web support modules (store, limits, abuse log, Turnstile)

**Files:**
- Create: `siteward/web/store.py`, `limits.py`, `abuse.py`, `turnstile.py`
- Test: `tests/test_store.py`, `tests/test_limits.py`, `tests/test_abuse.py`, `tests/test_turnstile.py`

**Interfaces:**
- Produces:
  - `store.Entry(scan_id, url, options)` with attrs `status` (`queued|running|done|error`), `results: list[CheckResult]`, `report: ScanReport | None`, `error: str`, `created`, `finished`, `started: datetime`, method `partial_report() -> ScanReport`
  - `store.Store(ttl=900, max_entries=20, clock=time.time)` with `create(url, options) -> Entry`, `get(scan_id) -> Entry | None`
  - `limits.SlidingWindow(limit, window, key: bytes, clock=time.monotonic)` with `allow(raw_key: str) -> bool`; `limits.Slots(concurrent, queue)` with `.sem` (a `threading.Semaphore`), `reserve() -> bool`, `release()`
  - `abuse.AbuseLog(directory, key: str, retention_days=30, enabled=True, clock=time.time)` with `record(ip, host, options, outcome)`, `target_hmac(host) -> str`; module function `lookup(directory, key, host) -> list[dict]`
  - `turnstile.verify(token, ip, secret, post=httpx.post) -> bool`

- [ ] **Step 1: Write the failing tests**

`tests/test_store.py`:
```python
from siteward.web.store import Store


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_create_and_get():
    store = Store(clock=Clock())
    entry = store.create("http://example.com/", {"ports": False})
    assert store.get(entry.id) is entry and entry.status == "queued"
    assert len(entry.id) >= 20  # unguessable


def test_unknown_id_returns_none():
    assert Store().get("nope") is None


def test_finished_entries_expire_after_ttl():
    clock = Clock()
    store = Store(ttl=900, clock=clock)
    entry = store.create("http://example.com/", {})
    entry.status, entry.finished = "done", clock.now
    clock.now += 899
    assert store.get(entry.id) is entry
    clock.now += 2
    assert store.get(entry.id) is None


def test_oldest_dropped_when_full():
    clock = Clock()
    store = Store(max_entries=2, clock=clock)
    first = store.create("http://a/", {})
    clock.now += 1
    second = store.create("http://b/", {})
    clock.now += 1
    third = store.create("http://c/", {})
    assert store.get(first.id) is None and store.get(second.id) and store.get(third.id)


def test_stuck_running_entries_are_eventually_dropped():
    clock = Clock()
    store = Store(clock=clock)
    entry = store.create("http://a/", {})
    clock.now += 3601
    assert store.get(entry.id) is None


def test_partial_report_reflects_results_so_far():
    from siteward.core.models import CheckResult

    entry = Store().create("http://example.com/", {"ports": False})
    entry.results.append(CheckResult("a", "T", "passed"))
    report = entry.partial_report()
    assert report.target == "http://example.com/" and len(report.results) == 1
```

`tests/test_limits.py`:
```python
from siteward.web.limits import SlidingWindow, Slots


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_allows_up_to_limit_then_blocks():
    w = SlidingWindow(2, 3600, b"k", clock=Clock())
    assert [w.allow("1.2.3.4") for _ in range(3)] == [True, True, False]


def test_keys_are_independent():
    w = SlidingWindow(1, 3600, b"k", clock=Clock())
    assert w.allow("a") and w.allow("b") and not w.allow("a")


def test_window_slides():
    clock = Clock()
    w = SlidingWindow(1, 100, b"k", clock=clock)
    assert w.allow("a") and not w.allow("a")
    clock.now += 101
    assert w.allow("a")


def test_raw_keys_are_not_stored_in_memory():
    w = SlidingWindow(5, 100, b"k", clock=Clock())
    w.allow("203.0.113.9")
    assert all("203.0.113.9" not in key for key in w._hits)


def test_slots_bound_running_plus_queue():
    slots = Slots(concurrent=1, queue=1)
    assert slots.reserve() and slots.reserve() and not slots.reserve()
    slots.release()
    assert slots.reserve()
```

`tests/test_abuse.py`:
```python
import json
import os
from datetime import datetime, timezone

from siteward.web.abuse import AbuseLog, lookup


class Clock:
    def __init__(self, ts):
        self.ts = ts

    def __call__(self):
        return self.ts


T0 = datetime(2026, 10, 15, 14, 2, tzinfo=timezone.utc).timestamp()


def test_record_writes_hashed_target_and_no_findings(tmp_path):
    log = AbuseLog(tmp_path, "secret", clock=Clock(T0))
    log.record("203.0.113.9", "Example.com", {"ports": False}, "accepted")
    text = next(tmp_path.glob("abuse-*.log")).read_text()
    line = json.loads(text.strip())
    assert line["ip"] == "203.0.113.9" and line["outcome"] == "accepted" and line["options"] == {"ports": False}
    assert "example.com" not in text.lower()
    assert line["target_hmac"] == log.target_hmac("example.com")


def test_lookup_finds_ip_from_reported_hostname(tmp_path):
    log = AbuseLog(tmp_path, "secret", clock=Clock(T0))
    log.record("203.0.113.9", "victim.example", {}, "accepted")
    log.record("198.51.100.1", "other.example", {}, "accepted")
    hits = lookup(tmp_path, "secret", "VICTIM.example")
    assert [h["ip"] for h in hits] == ["203.0.113.9"]
    assert lookup(tmp_path, "wrong-key", "victim.example") == []


def test_old_files_are_pruned(tmp_path):
    old = tmp_path / "abuse-2026-01-01.log"
    old.write_text("{}\n")
    log = AbuseLog(tmp_path, "secret", retention_days=30, clock=Clock(T0))
    log.record("203.0.113.9", "a.example", {}, "accepted")
    assert not old.exists()


def test_disabled_log_writes_nothing(tmp_path):
    AbuseLog(tmp_path, "secret", enabled=False, clock=Clock(T0)).record("1.1.1.1", "a.example", {}, "accepted")
    assert list(tmp_path.iterdir()) == []


def test_unwritable_directory_does_not_raise(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    AbuseLog(blocked / "sub", "secret", clock=Clock(T0)).record("1.1.1.1", "a.example", {}, "accepted")
```
(`import os` is unused; remove it when writing the file.)

`tests/test_turnstile.py`:
```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `pytest tests/test_store.py tests/test_limits.py tests/test_abuse.py tests/test_turnstile.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'siteward.web.store'`

- [ ] **Step 3: Implement**

`siteward/web/store.py`:
```python
"""In-memory result store. Nothing here ever touches disk."""
from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone

from siteward import __version__
from siteward.core.models import ScanReport

_STUCK_AFTER = 3600


class Entry:
    def __init__(self, scan_id, url, options, clock=time.time):
        self.id = scan_id
        self.url = url
        self.options = options
        self.status = "queued"  # queued | running | done | error
        self.results = []
        self.report = None
        self.error = ""
        self.created = clock()
        self.finished = None
        self.started = datetime.now(timezone.utc)

    def partial_report(self) -> ScanReport:
        return ScanReport(
            self.url, self.started, datetime.now(timezone.utc), __version__,
            {"ports": bool(self.options.get("ports"))}, list(self.results),
        )


class Store:
    def __init__(self, ttl=900, max_entries=20, clock=time.time):
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries = {}

    def _sweep(self):
        now = self._clock()
        for key, e in list(self._entries.items()):
            expired = (e.finished is not None and now - e.finished > self._ttl) or now - e.created > _STUCK_AFTER
            if expired:
                del self._entries[key]

    def create(self, url, options) -> Entry:
        with self._lock:
            self._sweep()
            while len(self._entries) >= self._max:
                oldest = min(self._entries.values(), key=lambda e: e.created)
                del self._entries[oldest.id]
            entry = Entry(secrets.token_urlsafe(16), url, options, clock=self._clock)
            self._entries[entry.id] = entry
            return entry

    def get(self, scan_id):
        with self._lock:
            self._sweep()
            return self._entries.get(scan_id)
```

`siteward/web/limits.py`:
```python
"""In-memory rate limiting. Keys are HMAC'd so raw IPs/hostnames are not held in memory tables."""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque


class SlidingWindow:
    def __init__(self, limit, window, key: bytes, clock=time.monotonic):
        self._limit, self._window, self._key, self._clock = limit, window, key, clock
        self._lock = threading.Lock()
        self._hits = {}
        self._last_sweep = clock()

    def _hash(self, raw: str) -> str:
        return hmac.new(self._key, raw.encode(), hashlib.sha256).hexdigest()

    def allow(self, raw_key: str) -> bool:
        key, now = self._hash(raw_key), self._clock()
        with self._lock:
            if now - self._last_sweep > 60:
                self._last_sweep = now
                for k in [k for k, q in self._hits.items() if not q or now - q[-1] > self._window]:
                    del self._hits[k]
            queue = self._hits.setdefault(key, deque())
            while queue and now - queue[0] > self._window:
                queue.popleft()
            if len(queue) >= self._limit:
                return False
            queue.append(now)
            return True


class Slots:
    """Bounds concurrent scans plus a small waiting queue."""

    def __init__(self, concurrent, queue):
        self.sem = threading.Semaphore(concurrent)
        self._cap = concurrent + queue
        self._n = 0
        self._lock = threading.Lock()

    def reserve(self) -> bool:
        with self._lock:
            if self._n >= self._cap:
                return False
            self._n += 1
            return True

    def release(self):
        with self._lock:
            self._n -= 1
```

`siteward/web/abuse.py`:
```python
"""Minimal abuse log: who started a scan, never what was found."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _hmac(key: str, host: str) -> str:
    return hmac.new(key.encode(), host.strip().lower().encode(), hashlib.sha256).hexdigest()


class AbuseLog:
    def __init__(self, directory, key, retention_days=30, enabled=True, clock=time.time):
        self._dir = Path(directory)
        self._key = key
        self._retention = retention_days
        self._enabled = enabled
        self._clock = clock
        self._lock = threading.Lock()

    def target_hmac(self, host: str) -> str:
        return _hmac(self._key, host)

    def record(self, ip, host, options, outcome):
        if not self._enabled:
            return
        now = datetime.fromtimestamp(self._clock(), timezone.utc)
        line = json.dumps({"ts": now.isoformat(), "ip": ip, "target_hmac": self.target_hmac(host),
                           "options": options, "outcome": outcome}, separators=(",", ":"))
        try:
            with self._lock:
                self._dir.mkdir(parents=True, exist_ok=True)
                with open(self._dir / f"abuse-{now:%Y-%m-%d}.log", "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._prune(now)
        except OSError:
            logger.warning("abuse log is not writable")  # never log scan details

    def _prune(self, now):
        for path in self._dir.glob("abuse-*.log"):
            try:
                day = datetime.strptime(path.stem.removeprefix("abuse-"), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if (now - day).days > self._retention:
                path.unlink(missing_ok=True)


def lookup(directory, key, host) -> list:
    """Return log lines whose target matches the reported hostname (for answering abuse reports)."""
    wanted, hits = _hmac(key, host), []
    for path in sorted(Path(directory).glob("abuse-*.log")):
        for raw in path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            if entry.get("target_hmac") == wanted:
                hits.append(entry)
    return hits


if __name__ == "__main__":  # python -m siteward.web.abuse DIRECTORY HOSTNAME   (key from ABUSE_LOG_KEY)
    import os

    for hit in lookup(sys.argv[1], os.environ["ABUSE_LOG_KEY"], sys.argv[2]):
        print(json.dumps(hit))
```

`siteward/web/turnstile.py`:
```python
import httpx

VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def verify(token, ip, secret, post=httpx.post) -> bool:
    if not token:
        return False
    try:
        response = post(VERIFY_URL, data={"secret": secret, "response": token, "remoteip": ip}, timeout=5)
        return bool(response.json().get("success"))
    except (httpx.HTTPError, ValueError):
        return False
```

- [ ] **Step 4: Run to verify they pass**

Run: `pytest tests/test_store.py tests/test_limits.py tests/test_abuse.py tests/test_turnstile.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add siteward/web/store.py siteward/web/limits.py siteward/web/abuse.py siteward/web/turnstile.py tests/test_store.py tests/test_limits.py tests/test_abuse.py tests/test_turnstile.py
git commit -m "feat(web): ephemeral store, in-memory rate limits, abuse log, Turnstile verifier" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 9b: Django app (settings, state, views, templates)

**Files:**
- Create: `siteward/web/settings.py`, `urls.py`, `wsgi.py`, `state.py`, `views.py`, `context.py`, `templates/base_bootstrap.html`, `templates/index.html`, `templates/scan.html`, `templates/_results.html`, `templates/policy.html`, `static/js/poll.js`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: Task 9a modules, `run_scan`, `discover_checks`, `render`/`FORMATS`, `validate_target`.
- Produces:
  - Settings (env-driven): `PUBLIC_MODE, TRUST_CF_HEADERS, TURNSTILE_SITE_KEY, TURNSTILE_SECRET, ABUSE_LOG, ABUSE_LOG_DIR, ABUSE_LOG_KEY, ABUSE_LOG_RETENTION_DAYS, RATE_PER_IP, RATE_PER_TARGET, RATE_WINDOW, MAX_CONCURRENT_SCANS, MAX_QUEUE, SCAN_TTL_SECONDS, MAX_STORED_SCANS, SCAN_MIN_INTERVAL, ALLOW_PRIVATE_TARGETS, THEME, DONATE_URL, CONTACT_EMAIL`
  - `state.get() -> State(store, ip_limiter, target_limiter, slots, abuse, total_checks)` and `state.reset()`
  - URL names: `index`, `scan_detail`, `scan_status`, `scan_export`, `policy`
  - `views._run(st, entry)` (the background thread body; tests monkeypatch it)
  - `views.client_ip(request) -> str`
  - Template context var `base_template` (from `context.theme`).

- [ ] **Step 1: Write the failing tests**

`tests/test_web.py`:
```python
import json
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
    assert b"Grade" in done.content and b"headers.security" in done.content
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
    text = next(__import__("pathlib").Path(settings.ABUSE_LOG_DIR).glob("abuse-*.log")).read_text()
    assert '"outcome":"accepted"' in text and "127.0.0.1" in text
    assert "example.com" not in text


def test_public_mode_still_refuses_private_targets(client, public, fake_dns):
    fake_dns["internal.example"] = "10.0.0.7"
    response = public_post(client, url="https://internal.example")
    assert response.status_code == 400 and b"Cannot scan" in response.content
```
(`HTTP_CF_CONNECTING_IP=...` keyword arguments are passed to the Django test client as WSGI environ keys, which is how a request header is simulated.)

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_web.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'siteward.web.settings'`

- [ ] **Step 3: Implement settings, urls, wsgi, state, context**

`siteward/web/settings.py`:
```python
import os
import secrets
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent


def _bool(name, default=False):
    return os.environ.get(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


def _int(name, default):
    return int(os.environ.get(name, default))


DEBUG = _bool("DEBUG")
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(50)  # no sessions are used, so a per-start key is fine
ALLOWED_HOSTS = [h for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h]
CSRF_TRUSTED_ORIGINS = [o for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if o]

# --- siteward -----------------------------------------------------------------------------------
PUBLIC_MODE = _bool("PUBLIC_MODE")
TRUST_CF_HEADERS = _bool("TRUST_CF_HEADERS")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")
ABUSE_LOG = _bool("ABUSE_LOG", default=PUBLIC_MODE)
ABUSE_LOG_DIR = os.environ.get("ABUSE_LOG_DIR", "/var/log/siteward")
ABUSE_LOG_KEY = os.environ.get("ABUSE_LOG_KEY", "")
ABUSE_LOG_RETENTION_DAYS = _int("ABUSE_LOG_RETENTION_DAYS", 30)
RATE_PER_IP = _int("RATE_PER_IP", 5)
RATE_PER_TARGET = _int("RATE_PER_TARGET", 3)
RATE_WINDOW = _int("RATE_WINDOW", 3600)
MAX_CONCURRENT_SCANS = _int("MAX_CONCURRENT_SCANS", 2)
MAX_QUEUE = _int("MAX_QUEUE", 5)
SCAN_TTL_SECONDS = _int("SCAN_TTL_SECONDS", 900)
MAX_STORED_SCANS = _int("MAX_STORED_SCANS", 20)
SCAN_MIN_INTERVAL = float(os.environ.get("SCAN_MIN_INTERVAL", "0.05"))
ALLOW_PRIVATE_TARGETS = _bool("ALLOW_PRIVATE_TARGETS")
THEME = os.environ.get("THEME", "bootstrap")
DONATE_URL = os.environ.get("DONATE_URL", "")
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "")

if PUBLIC_MODE:  # fail fast on a misconfigured public deployment (tests flip settings.PUBLIC_MODE after import)
    missing = [n for n, v in (("TURNSTILE_SECRET", TURNSTILE_SECRET), ("TURNSTILE_SITE_KEY", TURNSTILE_SITE_KEY)) if not v]
    if ABUSE_LOG and not ABUSE_LOG_KEY:
        missing.append("ABUSE_LOG_KEY")
    if missing:
        raise ImproperlyConfigured(f"PUBLIC_MODE requires: {', '.join(missing)}")

# --- Django (deliberately minimal: no database, sessions, auth or admin) --------------------------
DATABASES = {}
INSTALLED_APPS = ["django.contrib.staticfiles"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "siteward.web.middleware.SecurityHeadersMiddleware",
]
ROOT_URLCONF = "siteward.web.urls"
WSGI_APPLICATION = "siteward.web.wsgi.application"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "OPTIONS": {"context_processors": ["django.template.context_processors.request", "siteward.web.context.theme"]},
}]
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = Path(os.environ.get("STATIC_ROOT", Path.cwd() / "staticfiles"))
USE_TZ = True
CSRF_COOKIE_SECURE = PUBLIC_MODE
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
LOGGING = {"version": 1, "disable_existing_loggers": False, "root": {"level": "WARNING"}}
```
`siteward/web/wsgi.py`:
```python
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "siteward.web.settings")
application = get_wsgi_application()
```

`siteward/web/urls.py`:
```python
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("policy/", views.policy, name="policy"),
    path("scan/<str:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<str:scan_id>/status/", views.scan_status, name="scan_status"),
    path("scan/<str:scan_id>/export/", views.scan_export, name="scan_export"),
]
```

`siteward/web/state.py`:
```python
"""Process-wide singletons, built lazily from settings (tests call reset())."""
import os
import threading
from dataclasses import dataclass

from django.conf import settings

from siteward.core.runner import discover_checks

from .abuse import AbuseLog
from .limits import SlidingWindow, Slots
from .store import Store

_lock = threading.Lock()
_state = None


@dataclass
class State:
    store: Store
    ip_limiter: SlidingWindow
    target_limiter: SlidingWindow
    slots: Slots
    abuse: AbuseLog
    total_checks: int


def get() -> State:
    global _state
    with _lock:
        if _state is None:
            key = os.urandom(32)
            _state = State(
                store=Store(settings.SCAN_TTL_SECONDS, settings.MAX_STORED_SCANS),
                ip_limiter=SlidingWindow(settings.RATE_PER_IP, settings.RATE_WINDOW, key),
                target_limiter=SlidingWindow(settings.RATE_PER_TARGET, settings.RATE_WINDOW, key),
                slots=Slots(settings.MAX_CONCURRENT_SCANS, settings.MAX_QUEUE),
                abuse=AbuseLog(settings.ABUSE_LOG_DIR, settings.ABUSE_LOG_KEY, settings.ABUSE_LOG_RETENTION_DAYS,
                               enabled=settings.ABUSE_LOG),
                total_checks=len(discover_checks()),
            )
        return _state


def reset():
    global _state
    with _lock:
        _state = None
```

`siteward/web/context.py`:
```python
from django.conf import settings

from .settings import BASE_DIR


def theme(request):
    dashlite = BASE_DIR / "static" / "theme" / "dashlite" / "css" / "dashlite.css"
    use_dashlite = settings.THEME == "dashlite" and dashlite.exists()
    return {
        "base_template": "base_dashlite.html" if use_dashlite else "base_bootstrap.html",
        "donate_url": settings.DONATE_URL,
        "public_mode": settings.PUBLIC_MODE,
    }
```

- [ ] **Step 4: Implement views, middleware, templates, JS**

`siteward/web/middleware.py`:
```python
CSP = ("default-src 'self'; script-src 'self' https://challenges.cloudflare.com; "
       "frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", CSP)
        response.setdefault("Referrer-Policy", "no-referrer")
        response.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        return response
```

`siteward/web/views.py`:
```python
from __future__ import annotations

import logging
import threading
import time
from urllib.parse import urlsplit

from django.conf import settings
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from siteward.core.models import SEVERITIES
from siteward.core.netguard import BlockedTarget, validate_target
from siteward.core.runner import ScanError, run_scan
from siteward.reports import FORMATS

from . import state, turnstile

logger = logging.getLogger(__name__)
BADGE = {"critical": "danger", "high": "danger", "medium": "warning", "low": "info", "info": "secondary"}


def client_ip(request) -> str:
    if settings.TRUST_CF_HEADERS:
        forwarded = request.META.get("HTTP_CF_CONNECTING_IP", "").strip()
        if forwarded:
            return forwarded
    return request.META.get("REMOTE_ADDR", "")


def _host_of(url: str) -> str:
    try:
        return urlsplit(url if "://" in url else "https://" + url).hostname or ""
    except ValueError:
        return ""


def _run(st, entry):
    """Background thread body: waits for a slot, runs the scan, records the outcome in memory."""
    try:
        with st.slots.sem:
            entry.status = "running"
            entry.report = run_scan(entry.url, entry.options, on_result=entry.results.append)
            entry.status = "done"
    except BlockedTarget as exc:
        entry.error, entry.status = f"Refused: {exc}", "error"
    except ScanError as exc:
        entry.error, entry.status = str(exc), "error"
    except Exception as exc:  # never log details: they can contain the target
        logger.error("scan failed: %s", type(exc).__name__)
        entry.error, entry.status = "Unexpected error while scanning.", "error"
    finally:
        entry.finished = time.time()
        st.slots.release()


def _start_scan(request):
    """Returns (entry, error_message, http_status)."""
    st, ip = state.get(), client_ip(request)
    url = request.POST.get("url", "").strip()
    host = _host_of(url)

    if not request.POST.get("authorised"):
        return None, "Please confirm you are authorised to test this target.", 400
    if settings.PUBLIC_MODE and not turnstile.verify(request.POST.get("cf-turnstile-response", ""), ip, settings.TURNSTILE_SECRET):
        st.abuse.record(ip, host, {}, "captcha_failed")
        return None, "Verification failed. Please try again.", 400
    if not st.ip_limiter.allow(ip):
        st.abuse.record(ip, host, {}, "rate_limited")
        return None, "Rate limit reached. Please try again later.", 429

    allow_private = settings.ALLOW_PRIVATE_TARGETS and not settings.PUBLIC_MODE
    try:
        target = validate_target(url, allow_private)
    except BlockedTarget as exc:
        st.abuse.record(ip, host, {}, "blocked")
        return None, f"Cannot scan that target: {exc}", 400
    if not st.target_limiter.allow(target.host):
        st.abuse.record(ip, target.host, {}, "rate_limited")
        return None, "This site has been scanned too often recently. Please try again later.", 429
    if not st.slots.reserve():
        st.abuse.record(ip, target.host, {}, "busy")
        return None, "The scanner is busy. Please try again shortly.", 503

    ports = bool(request.POST.get("ports")) and not settings.PUBLIC_MODE
    options = {"ports": ports, "allow_private": allow_private, "min_interval": settings.SCAN_MIN_INTERVAL}
    entry = st.store.create(target.url, options)
    st.abuse.record(ip, target.host, {"ports": ports}, "accepted")
    threading.Thread(target=_run, args=(st, entry), daemon=True).start()
    return entry, "", 302


@require_http_methods(["GET", "POST"])
@never_cache
def index(request):
    context = {"turnstile_site_key": settings.TURNSTILE_SITE_KEY if settings.PUBLIC_MODE else "", "error": "", "url": ""}
    if request.method == "POST":
        entry, error, status = _start_scan(request)
        if entry:
            return redirect("scan_detail", scan_id=entry.id)
        context.update(error=error, url=request.POST.get("url", ""))
        return render(request, "index.html", context, status=status)
    return render(request, "index.html", context)


def _page(entry):
    st = state.get()
    report = entry.report or entry.partial_report()
    counts = [(s, report.counts[s], BADGE[s]) for s in reversed(SEVERITIES)]
    return {
        "entry": entry,
        "report": report,
        "findings": [{"f": f, "badge": BADGE[f.severity]} for f in report.findings],
        "passed": [r for r in report.results if r.status == "passed"],
        "skipped": [r for r in report.results if r.status == "skipped"],
        "errors": [r for r in report.results if r.status == "error"],
        "counts": counts,
        "done": entry.status in ("done", "error"),
        "completed": len(report.results),
        "total": st.total_checks,
    }


def _expired(request, status_only=False):
    response = render(request, "_results.html" if status_only else "scan.html",
                      {"expired": True}, status=404)
    response["X-Scan-Done"] = "1"
    return response


@require_GET
@never_cache
def scan_detail(request, scan_id):
    entry = state.get().store.get(scan_id)
    if entry is None:
        return _expired(request)
    return render(request, "scan.html", {**_page(entry), "scan_id": scan_id,
                                         "ttl_minutes": settings.SCAN_TTL_SECONDS // 60})


@require_GET
@never_cache
def scan_status(request, scan_id):
    entry = state.get().store.get(scan_id)
    if entry is None:
        return _expired(request, status_only=True)
    page = _page(entry)
    response = render(request, "_results.html", {**page, "scan_id": scan_id})
    response["X-Scan-Done"] = "1" if page["done"] else "0"
    return response


@require_GET
@never_cache
def scan_export(request, scan_id):
    entry = state.get().store.get(scan_id)
    if entry is None:
        raise Http404("scan expired")
    fmt = request.GET.get("format", "")
    if fmt not in FORMATS:
        return HttpResponse("format must be json, md or html", status=400)
    if entry.report is None:
        return HttpResponse("scan has not finished", status=409)
    render_fn, content_type, extension = FORMATS[fmt]
    response = HttpResponse(render_fn(entry.report), content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="siteward-report.{extension}"'
    return response


@require_GET
def policy(request):
    return render(request, "policy.html", {"contact_email": settings.CONTACT_EMAIL,
                                           "retention_days": settings.ABUSE_LOG_RETENTION_DAYS,
                                           "ttl_minutes": settings.SCAN_TTL_SECONDS // 60})
```

`siteward/web/templates/base_bootstrap.html`:
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}siteward{% endblock %}</title>
  {% load static %}
  <link rel="stylesheet" href="{% static 'vendor/bootstrap.min.css' %}">
</head>
<body>
<nav class="navbar border-bottom mb-4"><div class="container">
  <a class="navbar-brand" href="{% url 'index' %}">siteward</a>
  <a class="nav-link" href="{% url 'policy' %}">Policy &amp; privacy</a>
</div></nav>
<main class="container pb-5">{% block content %}{% endblock %}</main>
<footer class="container text-muted small pb-4">
  Only scan sites you own or are authorised to test.
  {% if donate_url %}&middot; <a href="{{ donate_url }}">Support this project</a>{% endif %}
</footer>
{% block scripts %}{% endblock %}
</body>
</html>
```

`siteward/web/templates/index.html`:
```html
{% extends base_template %}
{% block title %}siteward{% endblock %}
{% block content %}
<h1 class="h3">Scan a website</h1>
<p class="text-muted">Passive security checks. Results are shown here and are <strong>not stored</strong>: export anything you want to keep.</p>
{% if error %}<div class="alert alert-danger" role="alert">{{ error }}</div>{% endif %}
<form method="post" class="mb-3">
  {% csrf_token %}
  <div class="mb-3">
    <label for="url" class="form-label">Site URL</label>
    <input id="url" name="url" type="text" class="form-control" placeholder="https://example.com" value="{{ url }}" required>
  </div>
  <div class="form-check mb-2">
    <input class="form-check-input" type="checkbox" name="authorised" id="authorised">
    <label class="form-check-label" for="authorised">I am authorised to test this target.</label>
  </div>
  {% if not public_mode %}
  <div class="form-check mb-3">
    <input class="form-check-input" type="checkbox" name="ports" id="ports">
    <label class="form-check-label" for="ports">Include the TCP port check (opens connections to ~20 common ports).</label>
  </div>
  {% endif %}
  {% if turnstile_site_key %}<div class="cf-turnstile mb-3" data-sitekey="{{ turnstile_site_key }}"></div>{% endif %}
  <button class="btn btn-primary" type="submit">Run scan</button>
</form>
{% endblock %}
{% block scripts %}{% if turnstile_site_key %}<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>{% endif %}{% endblock %}
```

`siteward/web/templates/scan.html`:
```html
{% extends base_template %}
{% load static %}
{% block title %}Scan results{% endblock %}
{% block content %}
{% if expired %}
  <div class="alert alert-warning">This scan has expired or does not exist. Results are not stored on the server: run the scan again.</div>
  <a class="btn btn-primary" href="{% url 'index' %}">New scan</a>
{% else %}
  <div class="alert alert-secondary small">Results are not stored and expire {{ ttl_minutes }} minutes after the scan finishes. Export anything you want to keep.</div>
  <div id="results" data-status-url="{% url 'scan_status' scan_id %}">{% include "_results.html" %}</div>
{% endif %}
{% endblock %}
{% block scripts %}{% if not expired %}<script src="{% static 'js/poll.js' %}"></script>{% endif %}{% endblock %}
```

`siteward/web/templates/_results.html`:
```html
{% if expired %}
<div class="alert alert-warning">This scan has expired or does not exist. Results are not stored on the server: run the scan again.</div>
{% else %}
<h1 class="h4">Scan of {{ report.target }}</h1>
{% if entry.status == "error" %}
  <div class="alert alert-danger" role="alert">{{ entry.error }}</div>
{% elif not done %}
  <div class="alert alert-info">{% if entry.status == "queued" %}Queued...{% else %}Scanning... {{ completed }} of {{ total }} checks complete.{% endif %}</div>
{% else %}
  <p>Grade <span class="badge bg-dark fs-5">{{ report.grade }}</span>
  {% if report.incomplete %}<strong class="text-danger ms-2">Incomplete: some checks errored.</strong>{% endif %}</p>
  <p>{% for s, n, badge in counts %}<span class="badge bg-{{ badge }} me-1">{{ s }} {{ n }}</span>{% endfor %}</p>
  <p>
    <a class="btn btn-outline-secondary btn-sm" href="{% url 'scan_export' scan_id %}?format=json">Export JSON</a>
    <a class="btn btn-outline-secondary btn-sm" href="{% url 'scan_export' scan_id %}?format=md">Export Markdown</a>
    <a class="btn btn-outline-secondary btn-sm" href="{% url 'scan_export' scan_id %}?format=html">Export HTML</a>
  </p>
{% endif %}

{% if entry.status != "error" %}
<h2 class="h5 mt-4">Findings</h2>
{% if not findings %}<p class="text-muted">{% if done %}No findings.{% else %}None yet.{% endif %}</p>{% endif %}
{% for item in findings %}
<details class="border rounded p-2 mb-2">
  <summary><span class="badge bg-{{ item.badge }} me-2">{{ item.f.severity }}</span>{{ item.f.title }}</summary>
  {% if item.f.evidence %}<p class="mt-2 mb-1">Evidence:</p><pre class="bg-light p-2 small">{{ item.f.evidence }}</pre>{% endif %}
  {% if item.f.remediation %}<p><strong>Fix:</strong> {{ item.f.remediation }}</p>{% endif %}
</details>
{% endfor %}

{% if errors %}<h2 class="h5 mt-4 text-danger">Errored checks</h2><ul>{% for r in errors %}<li><code>{{ r.check_id }}</code>: {{ r.message }}</li>{% endfor %}</ul>{% endif %}
{% if skipped %}<h2 class="h5 mt-4">Skipped checks</h2><ul>{% for r in skipped %}<li><code>{{ r.check_id }}</code>: {{ r.message }}</li>{% endfor %}</ul>{% endif %}
{% if passed %}<details class="mt-4"><summary>Passed checks ({{ passed|length }})</summary><ul>{% for r in passed %}<li><code>{{ r.check_id }}</code></li>{% endfor %}</ul></details>{% endif %}
{% endif %}
{% endif %}
```

`siteward/web/templates/policy.html`:
```html
{% extends base_template %}
{% block title %}Policy &amp; privacy{% endblock %}
{% block content %}
<h1 class="h3">Usage policy &amp; privacy</h1>
<h2 class="h5 mt-4">Acceptable use</h2>
<p>This tool runs passive security checks. Only scan sites you own or are explicitly authorised to test. Scans are rate limited, and abuse may be reported to relevant parties.</p>
<h2 class="h5 mt-4">What we store</h2>
<ul>
  <li>Scan results are held in server memory only, for about {{ ttl_minutes }} minutes after a scan finishes, then discarded. They are never written to disk or a database.</li>
  <li>To handle abuse reports, we keep a minimal log for {{ retention_days }} days: time, your IP address, a keyed hash of the scanned hostname, which options were used, and the outcome. We do not log findings, page content or full URLs.</li>
  <li>Our network provider (Cloudflare) keeps its own request logs under its own policy.</li>
</ul>
<h2 class="h5 mt-4">Contact</h2>
<p>{% if contact_email %}Abuse reports and questions: <a href="mailto:{{ contact_email }}">{{ contact_email }}</a>{% else %}Contact details are set by the operator of this instance.{% endif %}</p>
{% endblock %}
```

`siteward/web/static/js/poll.js`:
```javascript
(function () {
  var box = document.getElementById("results");
  if (!box) { return; }
  var url = box.getAttribute("data-status-url");
  function tick() {
    fetch(url, { cache: "no-store" })
      .then(function (response) {
        var done = response.headers.get("X-Scan-Done") === "1";
        return response.text().then(function (html) { box.innerHTML = html; return done; });
      })
      .then(function (done) { if (!done) { setTimeout(tick, 1000); } })
      .catch(function () { setTimeout(tick, 3000); });
  }
  setTimeout(tick, 1000);
})();
```

- [ ] **Step 5: Run to verify it passes**

Run: `pytest tests/test_web.py -v`
Expected: all PASS. If `test_index_renders_form` fails because `base_bootstrap.html` references a static file that does not exist, that is expected only in non-debug mode with manifest storage; the default `StaticFilesStorage` does not check, so it should pass.

- [ ] **Step 6: Run the full suite and commit**

Run: `pytest -q`
Expected: all PASS

```bash
git add siteward/web tests/test_web.py
git commit -m "feat(web): database-less Django UI with live results, exports, public-mode protections" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Vendored Bootstrap and the DashLite theme hook

**Files:**
- Create: `siteward/web/static/vendor/bootstrap.min.css` (downloaded), `siteward/web/static/vendor/BOOTSTRAP_LICENSE.txt`, `siteward/web/templates/base_dashlite.html`
- Test: add `test_theme_hook_*` to `tests/test_web.py`

**Interfaces:**
- Consumes: `context.theme` (Task 9b) which returns `base_dashlite.html` only when `THEME=dashlite` and `siteward/web/static/theme/dashlite/css/dashlite.css` exists.
- Produces: default Bootstrap skin; optional DashLite skin using the same page blocks.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_web.py`:
```python
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
```

- [ ] **Step 2: Run to verify the DashLite test fails**

Run: `pytest tests/test_web.py -k theme -v`
Expected: `test_dashlite_used_when_present` FAILS with `TemplateDoesNotExist: base_dashlite.html`

- [ ] **Step 3: Vendor Bootstrap and add the DashLite skin**

```bash
mkdir -p siteward/web/static/vendor
curl -fsSL https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css -o siteward/web/static/vendor/bootstrap.min.css
curl -fsSL https://raw.githubusercontent.com/twbs/bootstrap/v5.3.3/LICENSE -o siteward/web/static/vendor/BOOTSTRAP_LICENSE.txt
head -c 200 siteward/web/static/vendor/bootstrap.min.css
```
Expected: the CSS begins with a Bootstrap v5.3.3 banner comment.

`siteward/web/templates/base_dashlite.html` (same blocks as the Bootstrap base; the page templates use only generic Bootstrap-compatible classes, so they render under DashLite too):
```html
<!doctype html>
<html lang="en" class="js">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}siteward{% endblock %}</title>
  {% load static %}
  <link rel="stylesheet" href="{% static 'theme/dashlite/css/dashlite.css' %}">
</head>
<body class="nk-body bg-lighter">
<div class="nk-app-root"><div class="nk-wrap">
  <div class="nk-header bg-white border-bottom"><div class="container-fluid d-flex justify-content-between py-3">
    <a class="fw-bold" href="{% url 'index' %}">siteward</a>
    <a href="{% url 'policy' %}">Policy &amp; privacy</a>
  </div></div>
  <div class="nk-content"><div class="container py-4">
    {% block content %}{% endblock %}
  </div></div>
  <div class="container text-muted small pb-4">
    Only scan sites you own or are authorised to test.
    {% if donate_url %}&middot; <a href="{{ donate_url }}">Support this project</a>{% endif %}
  </div>
</div></div>
{% block scripts %}{% endblock %}
</body>
</html>
```
(Do NOT load DashLite JS bundles: the CSP only allows our own `poll.js` and Turnstile. The skin is CSS-only by design.)

- [ ] **Step 4: Run to verify it passes, then commit**

Run: `pytest tests/test_web.py -k theme -v` then `pytest -q`
Expected: all PASS

```bash
git status --short   # confirm nothing under siteward/web/static/theme/ is staged
git add siteward/web/static/vendor siteward/web/templates/base_dashlite.html tests/test_web.py
git commit -m "feat(web): vendored Bootstrap skin and optional git-ignored DashLite theme hook" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Packaging, docs, and end-to-end verification

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `CONTRIBUTING.md`, `SECURITY.md`
- Modify: `README.md` (replace the stub)

**Interfaces:**
- Consumes: everything above.
- Produces: a runnable container image definition and contributor/user docs.

- [ ] **Step 1: Write the Dockerfile and `.dockerignore`**

`Dockerfile`:
```dockerfile
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DJANGO_SETTINGS_MODULE=siteward.web.settings
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY siteward ./siteward
RUN pip install --no-cache-dir . \
 && STATIC_ROOT=/app/staticfiles django-admin collectstatic --noinput \
 && useradd --system --no-create-home app \
 && mkdir -p /var/log/siteward && chown app /var/log/siteward
ENV STATIC_ROOT=/app/staticfiles
USER app
EXPOSE 8000
# One worker + threads: scan results live in this process's memory. No access log by design.
CMD ["gunicorn", "siteward.web.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "60"]
```

`.dockerignore`:
```
.venv
.git
docs
tests
__pycache__
*.egg-info
staticfiles
siteward/web/static/theme
```

- [ ] **Step 2: Write `README.md`**

````markdown
# siteward

A small, self-hostable **passive** web security scanner. Give it a URL, it runs a set of standard checks and shows you the findings; export them as JSON, Markdown, or a self-contained HTML file. **Nothing about scanned sites is stored.**

> Only scan sites you own or are explicitly authorised to test. This is a routine-coverage tool; it does not replace a manual penetration test.

## What it checks (v1)

Security headers (CSP, HSTS, framing, nosniff, referrer, permissions) · TLS certificate and legacy protocols · HTTP→HTTPS redirect · cookie flags · CORS misconfiguration · exposed files (`.git`, `.env`, backups, dumps, directory listing) · information leakage · `security.txt` / `robots.txt` · SPF / DKIM / DMARC · dangling CNAME / subdomain takeover hints · **opt-in** TCP port check (~20 common ports).

Active tests (XSS/injection probes) are planned for v2 behind an ownership check.

## Quick start

```bash
pip install .                      # Python 3.11+
siteward scan https://example.com   # Markdown report to stdout
siteward scan https://example.com --format html --out report.html
siteward scan https://example.com --ports --fail-on medium   # exit 1 if medium+ findings (CI-friendly)
```

Web UI (local):
```bash
DEBUG=1 django-admin runserver --settings=siteward.web.settings
```
Docker:
```bash
docker build -t siteward .
docker run -p 8000:8000 -e SECRET_KEY=change-me -e ALLOWED_HOSTS=localhost siteward
```

The web app has **no login**. Run it on localhost, or behind your own auth/VPN, or use the public-mode setup below.

## Privacy: nothing is stored

There is no database. Web results live in server memory for 15 minutes after a scan finishes, then vanish; exports stream straight to you. Logs never contain targets or findings.

## Public instance (free, behind Cloudflare)

One container behind Cloudflare, with `PUBLIC_MODE=1`. Required env vars: `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET`, `ABUSE_LOG_KEY`; also set `TRUST_CF_HEADERS=1` **only if the container is reachable solely through Cloudflare** (firewall to Cloudflare IP ranges), `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `SECRET_KEY`, `CONTACT_EMAIL`, and optionally `DONATE_URL`.

Public mode: Turnstile on the form, per-IP (5/h) and per-target (3/h) limits, max 2 concurrent scans, the port check forced off, private targets always refused, and a minimal abuse log (`time, IP, keyed hash of target, options, outcome`; 30 days). To answer an abuse report ("example.com was scanned at 14:02"):

```bash
ABUSE_LOG_KEY=... python -m siteward.web.abuse /var/log/siteward example.com
```

Behind Cloudflare also add a WAF rate-limiting rule for the scan form (free tier) as the first line of defence. Mount `/var/log/siteward` as the only writable volume.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_MODE` | off | Turnstile, restrictions and abuse log for a public instance |
| `TRUST_CF_HEADERS` | off | Read the client IP from `CF-Connecting-IP` |
| `RATE_PER_IP` / `RATE_PER_TARGET` / `RATE_WINDOW` | 5 / 3 / 3600 | Scans per window |
| `MAX_CONCURRENT_SCANS` / `MAX_QUEUE` | 2 / 5 | Concurrency and waiting queue |
| `SCAN_TTL_SECONDS` | 900 | How long finished results stay in memory |
| `ALLOW_PRIVATE_TARGETS` | off | Scan private/LAN addresses (never in public mode) |
| `THEME` | bootstrap | `dashlite` to use a locally installed DashLite skin |
| `ABUSE_LOG`, `ABUSE_LOG_DIR`, `ABUSE_LOG_KEY`, `ABUSE_LOG_RETENTION_DAYS` | on in public mode | Minimal abuse log |
| `DONATE_URL`, `CONTACT_EMAIL` | empty | Shown in the footer / policy page |

## Themes

The default skin is Bootstrap 5 (MIT, vendored). If you own a licence for the commercial DashLite template, copy **your original, unmodified** package's CSS/fonts/images into `siteward/web/static/theme/dashlite/` (so `css/dashlite.css` exists) and set `THEME=dashlite`. That folder is git-ignored; do not redistribute DashLite files.

## Known limits

- Passive checks cannot prove a site is secure; "no findings" means "nothing found by these checks".
- Port checks on sites behind a CDN (e.g. Cloudflare) only see the CDN edge.
- DNS is resolved once for validation and again when connecting; a hostile resolver could rebind between the two.

MIT licensed. See `CONTRIBUTING.md` to add a check and `SECURITY.md` to report a vulnerability.
````

- [ ] **Step 3: Write `CONTRIBUTING.md` and `SECURITY.md`**

`CONTRIBUTING.md`:
````markdown
# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Tests never touch the internet: use the local `server` fixture (`tests/fake_server.py`), `httpx.MockTransport`, and the `fake_dns` fixture.

## Adding a check

A check is one module in `siteward/checks/`. The runner discovers it automatically.

```python
# siteward/checks/example.py
from siteward.core.models import Finding, Skip

ID = "example.thing"        # unique
CATEGORY = "Example"
OPT_IN = None               # or an option name (e.g. "ports") if the check must be switched on explicitly


def run(ctx):
    # ctx.target (url, scheme, host, port, ips), ctx.baseline (the page, already fetched),
    # ctx.client.get(url) -> Fetch (status, headers, body, text). Always use ctx.client for requests.
    if ctx.target.scheme != "https":
        raise Skip("only applies to HTTPS")
    return [Finding("example.problem", "Short title", CATEGORY, "medium", "evidence", "how to fix")]
```

Rules: be passive by default; never put secret values (file contents, cookie values) in evidence; treat everything from the target as hostile text; add a good-case and bad-case test.

Never commit DashLite or other commercial assets.
````

`SECURITY.md`:
````markdown
# Security policy

Please report vulnerabilities in siteward privately to the maintainers (see the contact on the project page) rather than opening a public issue. Include steps to reproduce. We aim to acknowledge reports within a few days.

Areas of particular interest: bypasses of the target validation in `siteward/core/netguard.py` (SSRF), rate-limit bypasses, injection into generated reports, and anything that causes scan data to be persisted.
````

- [ ] **Step 4: Full verification**

```bash
. .venv/bin/activate
pytest -q
```
Expected: all tests PASS.

Smoke-test the CLI against a real public site you own (this is the only step that uses the internet; use DevBridge's own site):
```bash
siteward scan https://<your-devbridge-site> --format html --out /tmp/siteward-smoke.html --fail-on never
```
Expected: exits 0; stderr shows one line per check; the HTML file opens in a browser with a grade, findings, and passed/skipped sections; `ports.common` shows as skipped.

Smoke-test the web UI:
```bash
DEBUG=1 ALLOW_PRIVATE_TARGETS=1 django-admin runserver --settings=siteward.web.settings
```
Open http://127.0.0.1:8000, scan your own site, confirm: live progress, results page, export buttons download files, `Cache-Control: no-store` on results, no scan data written anywhere (`find . -newer pyproject.toml -name '*.sqlite*'` finds nothing).

Build the image (if Docker is available): `docker build -t siteward .` — Expected: builds without error.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore README.md CONTRIBUTING.md SECURITY.md
git commit -m "docs: README, contributing guide, security policy, Dockerfile" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```
