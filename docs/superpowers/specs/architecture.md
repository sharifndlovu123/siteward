# Architecture — webscan (v1)

Companion to `2026-10-15-web-security-scanner-design.md`. That doc says *what* we build; this one says
*how it fits together*. Guiding rule: **small enough to read in an afternoon, cheap enough to host on
the smallest box.** Every piece below has to earn its place.

## 1. Complexity budget

| Decision | Choice | Why |
|---|---|---|
| Processes | **One** (Django, scans in a thread) | No Redis, Celery, worker, or broker to host or monitor |
| Database | **None.** Results live in process memory only, briefly, and are never written to disk | Nothing stored means nothing to leak, back up, or migrate (see §3a) |
| Runtime deps | Django, httpx, dnspython, Jinja2 (+ Typer for CLI) | Four or five libraries; TLS and ports use the stdlib |
| JavaScript | A ~30-line polling snippet, no framework, no build step | Nothing to compile or bundle |
| Front-end assets | Bootstrap CSS vendored as static files | No Node, no npm |
| Config | A few env vars | No config files or settings UI |
| Auth | None in v1 (documented: self-host behind your own auth/VPN) | Accounts are a big surface; skip until needed |

Cuts relative to the spec: `sslyze` dropped (stdlib `ssl` is enough for v1); Typer is the only CLI
dependency; compare/diff, scheduling, and PDF stay out.

## 2. Shape of the system

```
            ┌────────────┐        ┌──────────────┐
  browser → │  web/      │        │  cli/        │ ← terminal / CI
            │  (Django)  │        │  (Typer)     │
            └─────┬──────┘        └──────┬───────┘
                  │  scan(url, opts)     │
                  └──────────┬───────────┘
                       ┌─────▼──────┐
                       │   core/    │  validate → fetch once → run checks → ScanReport
                       └─────┬──────┘
              ┌──────────────┼───────────────┐
        ┌─────▼─────┐  ┌─────▼─────┐   ┌─────▼─────┐
        │  checks/  │  │  reports/ │   │ netguard  │
        │ 1 file ea │  │ json/html/│   │ (SSRF +   │
        └───────────┘  │ markdown  │   │ rate cap) │
                       └───────────┘   └───────────┘
```

**Dependency rule (the one rule that keeps it simple):** arrows only point downward. `core/` and
`checks/` never import Django or Typer. `web/` and `cli/` never contain scan logic.

## 3. Components and contracts

### `core/models.py` — plain dataclasses
- `Finding(id, title, category, severity, evidence, remediation)`
- `CheckResult(check_id, status, findings, message)` — status: `passed | findings | skipped | error`
- `ScanReport(target, started, finished, version, options, results)` — severity counts and grade are
  computed properties, not stored.

No ORM objects here; Django maps to and from these at the edge.

### `core/context.py` — `ScanContext`
Built once per scan after target validation. Holds: normalised `target`, shared `httpx.Client`
(already wrapped by `netguard`), the baseline response (headers, body, cookies, redirect chain),
resolved IPs, and `options`. Checks read from it, so the page is fetched once, not once per check.

### `checks/` — the plugin contract
```python
# checks/security_headers.py
ID = "headers.security"
CATEGORY = "Headers"
NEEDS_OPT_IN = False          # True only for the port check

def run(ctx: ScanContext) -> list[Finding]: ...
```
- A check is a module with `ID`, `CATEGORY`, `NEEDS_OPT_IN`, and `run`. No base class, no registry
  decorators.
- Discovery: the runner imports every module in `checks/` (`pkgutil.iter_modules`) and skips
  opt-in checks unless enabled in `options`.
- A check returns findings, or an empty list for "fine". It may raise; the runner converts that into
  an `error` result.

### `core/runner.py`
`run_scan(url, options, on_result=None) -> ScanReport`
1. `netguard.validate(url)` → `ScanContext` (baseline fetch included).
2. Run checks in a `ThreadPoolExecutor` (max ~8 workers, per-check timeout).
3. Call `on_result(CheckResult)` as each completes (the web UI uses this for live progress; the CLI
   uses it for a progress line; both are optional).
4. Return the `ScanReport`.

Threads, not asyncio: checks are short I/O-bound functions, plain sync code is easiest to read and
test, and Django is happy with it.

### `core/netguard.py` — the safety layer (one small module, used by everything)
- `validate(url)`: http/https only; resolve DNS; reject private, loopback, link-local, and
  metadata ranges (`169.254.169.254`, etc.).
- A custom `httpx` transport/event hook that **re-validates every redirect hop** and applies the
  global request-rate cap. Checks get their HTTP client only through `ctx`, so they cannot bypass it.
- The port check also goes through `netguard` (it may only target IPs `validate` approved).
- Fixed `User-Agent` string identifying the tool; default timeouts.

### `reports/`
`to_json(report)`, `to_markdown(report)`, `to_html(report)`: pure functions of a `ScanReport`. HTML is
one Jinja2 template with inline CSS (self-contained attachment). No state, trivially snapshot-tested.

### `cli/`
One Typer command: `webscan scan URL [--ports] [--format json|md|html] [--out FILE]`. Calls
`run_scan`, calls a `reports` function, prints or writes the result. No database. Exit code is
non-zero when findings at or above `--fail-on` severity exist, so it works in CI for free.

### `web/` (Django)
- **No models, no database.** Django runs with no `DATABASES` entry, and sessions use signed cookies,
  so there are no migrations and nothing on disk. See §3a for how results are held.
- **Views (4):** `new` (GET/POST form), `scan_detail` (results page), `scan_status` (JSON for
  polling), `scan_export` (`?format=`). There is no history page and no delete view.
- **Background run:** POST creates an in-memory scan entry (status `running`), starts one
  `threading.Thread` that calls `run_scan(..., on_result=...)`, and redirects to the results page.
  `on_result` appends to the entry's partial report; the page polls `scan_status` every ~1s. On
  finish the thread stores the final report in memory.
- **Restart behaviour:** a restart wipes everything, which is the intended behaviour. A page open
  during a restart shows "scan expired, run it again".
- **Concurrency cap:** a module-level semaphore (default 2 simultaneous scans) so a small host is not
  overwhelmed; extra requests show "queued".

### 3a. Ephemeral result store (`web/store.py`, ~40 lines)
- A dict `{scan_id: entry}` guarded by a lock, held in RAM only. `scan_id` comes from
  `secrets.token_urlsafe(16)`, so it cannot be guessed.
- Each entry has a **TTL (default 15 minutes after completion)**; a lazy sweep on each request drops
  expired entries. Results are meant to be read as they appear and exported if you want a copy.
- Entries are capped (e.g. 20) so memory stays bounded; the oldest are dropped first.
- **No logging of targets or findings.** Application logs record only generic events (scan started,
  finished, error class), never the URL, evidence, or report. Access logs are configured to omit the
  scan ID path as well. The single exception is the minimal abuse log in §10.3.
- Responses for results and exports send `Cache-Control: no-store`, so browsers and proxies do not
  keep copies. Exports are streamed to the user, never written to server disk.
- Single gunicorn worker (already the plan), because the store is per-process.
- Trade-off, accepted deliberately: no history, no "compare to last scan", and a restart loses
  in-flight and recent results. The export file is the only copy, and it is the user's to keep.
- **Templates:** `base.html` + 3 page templates. Theme hook: `base.html` picks the skin from
  `THEME` env var; if `THEME=dashlite` and `web/static/theme/dashlite/` exists it loads that skin,
  otherwise Bootstrap. Content blocks are shared.

## 4. Data flow (web scan)

```
POST /scan  →  create in-memory entry(running)  →  spawn thread  →  redirect /scan/<id>
thread: run_scan → netguard.validate → baseline fetch → checks (parallel)
        each result → on_result → update in-memory partial report
        done → keep final report in RAM until TTL expires, status=done
browser: GET /scan/<id>/status (poll) → render rows as they arrive → export links
TTL expiry or restart → entry gone; nothing was ever written to disk
```

## 5. Hosting footprint

- One container: `gunicorn` with 1 worker and several threads (so the in-process scan thread and page
  requests coexist), WhiteNoise for static files (no separate web server needed for small
  deployments). **No volume and no database**; the container can run with a read-only filesystem.
- Env vars only: `SECRET_KEY`, `ALLOWED_HOSTS`, `THEME` (optional), `MAX_CONCURRENT_SCANS` (optional),
  `ALLOW_PRIVATE_TARGETS` (default off; for scanning your own LAN in a dev setup), plus the public
  instance settings in §10 (`PUBLIC_MODE`, `TRUST_CF_HEADERS`, `TURNSTILE_SECRET`, `ABUSE_LOG_KEY`,
  rate-limit numbers).
- Idle cost is near zero; memory is dominated by Django itself.
- The public DevBridge instance runs as one container behind Cloudflare (proxied DNS), with
  `PUBLIC_MODE=1` (§10). Self-hosters who skip Cloudflare should bind to localhost or place it behind
  their own auth/VPN, since the app itself has no login.

## 6. Where v2 plugs in (no rework needed)

- **Active checks:** same plugin contract, with `ACTIVE = True`. The runner skips them unless
  `options.active` is on **and** an ownership proof exists.
- **Ownership check:** one new module `core/ownership.py` (DNS TXT or `/.well-known/` file lookup)
  called from `run_scan` before enabling active checks. `netguard` rate caps already apply.
- Nothing in `web/` or `reports/` changes except one extra form checkbox.

## 7. Testing strategy

- `tests/fake_server.py`: a tiny local HTTP server (stdlib `http.server`) with switchable "good" and
  "bad" profiles (missing headers, exposed `.env`, bad cookies, permissive CORS). Each check has a
  good-case and bad-case test.
- `netguard` tests: private IPs, redirects to internal addresses, non-http schemes.
- Runner tests: a check that raises, a check that hangs (timeout), result ordering.
- Reports: snapshot tests for JSON, Markdown, and HTML.
- Django: a few view tests (create scan, poll status, export, delete) with `run_scan` stubbed.
- The suite needs no internet and no running services.

## 8. Repo layout

```
webscan/
├── core/        models.py  context.py  runner.py  netguard.py
├── checks/      one module per check
├── reports/     json.py  markdown.py  html.py  report.html.j2
├── cli/         main.py
├── web/         manage.py  settings.py  scans/ (store.py, views, urls, templates, static)
├── tests/
├── Dockerfile   pyproject.toml   README.md   CONTRIBUTING.md   SECURITY.md   LICENSE
```

## 9. Open questions for review

1. **Resolved: no persistence.** Per your requirement, nothing about scanned sites is stored; results
   exist only in memory for a short TTL (§3a). History and scan comparison are therefore out of scope,
   not just deferred.
2. **Resolved: the hosted instance is public and free.** No login; protection comes from the layered
   rate limiting, Turnstile, and the minimal abuse log in §10.

## 10. Public hosting: rate limiting and abuse handling

The DevBridge instance is free and public, one container behind Cloudflare. All of this is gated by
`PUBLIC_MODE=1`; self-hosters and the CLI can run without it.

### 10.1 Layered rate limiting (nothing persisted)
1. **Cloudflare edge:** a free-tier WAF rate-limiting rule per IP, and **Turnstile** on the scan form.
   The app verifies the Turnstile token server-side (`TURNSTILE_SECRET`) before starting a scan.
2. **Per-IP limit:** default 5 scans/hour/IP.
3. **Per-target limit:** default 3 scans/hour per hostname, so the service cannot be used to hammer
   someone else's site.
4. **Global caps:** `MAX_CONCURRENT_SCANS` (default 2) plus a small bounded queue; when full, return
   "busy, try again shortly".

Counters live in an in-memory `rate_limit.py` (~40 lines): sliding-window dicts keyed by a keyed hash
of the IP or hostname, with entries expiring after the window. Restart resets them, which is
acceptable because Cloudflare's edge limit still applies.

The client IP is read from `CF-Connecting-IP` only when `TRUST_CF_HEADERS=1`; otherwise the socket
address is used. The container must be reachable only via Cloudflare in public mode (firewall to
Cloudflare IP ranges) so the header cannot be spoofed.

### 10.2 Public-mode restrictions
- **Port check disabled** on the public instance (`PUBLIC_MODE` forces it off); still available in the
  CLI and on self-hosted instances. Open port scanning is the riskiest feature to offer anonymously.
- Only the passive v1 checks run. v2 active checks (when they exist) will require the ownership proof.
- The "I'm authorised to test this target" checkbox stays, along with a short usage policy page
  (terms, what is logged, who to contact for abuse).
- Private/internal targets are always refused (`netguard`), regardless of config.

### 10.3 Minimal abuse log (attribution without storing what was found)
One structured line per scan start, written to an append-only log file with automatic deletion after
30 days (`ABUSE_LOG_RETENTION_DAYS`):

```
{ts, client_ip, target_hmac, options, outcome}
```
- `target_hmac` = HMAC-SHA256 of the lowercase hostname with `ABUSE_LOG_KEY`. A leaked log reveals IPs
  and opaque tokens, not which sites were researched. To answer an abuse report ("example.com was
  scanned at 14:02"), the operator HMACs the reported hostname and searches the log for the match,
  which yields the originating IP.
- **Never logged:** findings, evidence, report content, full URLs, page content, Turnstile tokens.
- The log lives in a small mounted directory (the only writable path; the rest of the container stays
  read-only). It can be disabled with `ABUSE_LOG=0` for self-hosters.
- IP addresses are personal information under POPIA, so the public instance publishes a short privacy
  notice stating what is logged, why, and for how long. Cloudflare keeps its own request logs
  separately, under its own retention.

### 10.4 Donations
A "support this project" link on the static pages (e.g. a donation platform URL from an env var or
template). No payments handling in the app, so no new dependencies or data.
