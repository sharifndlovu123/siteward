# Web Security Scanner — Design (v1)

**Date:** 2026-10-15
**Status:** Draft for review
**Project name:** TBD (placeholder: `webscan`)
**Licence:** MIT

## 1. Purpose

An open-source, self-hosted Python tool. The user supplies a URL; the tool runs a set of standard,
non-exotic security checks and produces a findings report that is viewable in a web UI and
exportable as a file. It exists so DevBridge can run routine security testing in-house on its own
site and on the static sites it builds, instead of paying for outsourced pentests for routine
coverage. It does not replace a full manual pentest.

### In scope (v1)
- Passive checks against a target URL, plus an opt-in TCP port check.
- CLI, web UI (full results shown on the page), and exports (JSON, HTML, Markdown).
- Plugin-style checks so new test types are cheap to add.

### Out of scope (v1)
- Active/hostile-input testing (XSS and injection probes, form fuzzing, wordlist brute force) — **v2**, behind an ownership check.
- PDF export (later; can be produced by printing the HTML report).
- User accounts, multi-tenancy, scheduled scans, scan diffing, CVE/outdated-library detection (later).

### Assumptions
- Targets are sites the operator owns or is authorised to test (DevBridge's site and sites it builds).
- Two ways to run it: self-hosted (localhost or behind the operator's own auth), and a free public
  DevBridge instance (one container behind Cloudflare). The app has no login in v1; the public instance
  is protected by layered rate limiting, Turnstile, public-mode restrictions, and a minimal abuse log
  (see `architecture.md` §10).

## 2. Architecture

One repository, with the scanner independent of the web layer:

```
core/      Finding model, Check base class, runner, ScanContext, target validation
checks/    one file per check; each exposes run(ctx) -> list[Finding]
reports/   exporters: JSON, HTML, Markdown (all built from one ScanReport)
cli/       Typer app:  scan <url> [--ports] [--format json|html|md] [--out FILE]
web/       Django app: scan form, results page, history, export endpoints
tests/     per-check tests against a local fake server
```

- `cli/` and `web/` contain no scan logic; both call `core`.
- A new check is one file in `checks/`; the runner discovers it automatically.

### Stack
Python 3.11+, Django (web, no database), Typer (CLI), httpx (requests), dnspython (DNS),
stdlib `ssl`/`socket` (TLS and port checks; `sslyze` only if stdlib proves insufficient), Jinja2
(HTML/Markdown report rendering), pytest.

## 3. Data model

- **Finding:** `id`, `title`, `category`, `severity` (info|low|medium|high|critical), `evidence`, `remediation`.
- **CheckResult:** `check_id`, `status` (passed | findings | skipped | error), `findings`, optional `message`.
- **ScanReport:** target, started/finished timestamps, tool version, options used (e.g. ports on/off),
  list of `CheckResult`, severity counts, letter grade (A–F, based on worst findings; a convenience
  only — findings are the real output).
- **No persistence.** Neither the CLI nor the web app uses a database or writes scan data to disk.
  The web app keeps results in process memory only, for a short TTL (default 15 min), so they can be
  read and exported and are then gone. Scanned targets and findings are never logged. The one
  exception is the public instance's minimal abuse log (timestamp, client IP, keyed hash of the target
  hostname, options, outcome; 30-day retention), which allows responding to abuse reports without
  storing what was found.

## 4. Scan lifecycle

1. **Validate target.** Normalise URL; allow only http/https; resolve DNS; reject private, loopback,
   and link-local addresses (SSRF guard). Repeat the check on every redirect hop.
2. **Baseline fetch.** One shared request captures headers, body, cookies, and redirect chain into a
   `ScanContext`, so checks do not each re-request the page.
3. **Run checks.** Concurrent with a small worker limit and a global request-rate cap. A check that
   raises or times out yields an `error` `CheckResult`; the scan continues.
4. **Assemble `ScanReport`.** Findings sorted by severity. Passed, skipped, and errored checks are
   all listed ("checked and fine" is part of the report; an errored check is never shown as a pass).

Safety defaults: clear `User-Agent`, timeouts, rate limiting, private-IP refusal, and an
"authorised targets only" notice in the CLI and UI.

## 5. Checks (v1)

All passive unless stated.

| Category | Check |
|---|---|
| Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| TLS | Protocol versions, certificate validity/expiry, chain, hostname match |
| Transport | HTTP→HTTPS redirect, mixed content hints |
| Cookies | Secure, HttpOnly, SameSite flags |
| CORS | Wildcard/reflected-origin misconfiguration |
| Exposure | `.git`, `.env`, backup/config files, directory listing (small fixed path list) |
| Leakage | Server/X-Powered-By version disclosure, verbose error pages |
| Policy files | `security.txt`, `robots.txt` review |
| DNS/Email | SPF, DKIM (common selectors), DMARC |
| DNS | Subdomain-takeover hints (dangling CNAME) |
| Ports (**opt-in**) | TCP connect on ~20 common ports (SSH, FTP, Telnet, SMB, RDP, common DBs, etc.). Off by default; enabling shows the authorised-targets notice. |

The port check is disabled on the public hosted instance (`PUBLIC_MODE`); it remains available in the
CLI and on self-hosted instances.

Note: for sites behind Cloudflare, the port check sees Cloudflare's edge, not the origin; the docs say so.

## 6. Web UI

Server-rendered Django templates, minimal JavaScript.

- **Home / new scan:** URL field; "Include port check" checkbox; required "I'm authorised to test this target" checkbox.
- **Results page (primary output):** header (target, date, version, options, severity counts, grade);
  live progress while the scan runs (checks appear as they finish); findings sorted by severity,
  expandable to show evidence and fix advice, filterable by severity/category; collapsed passed-checks
  section; clearly shown errored/skipped checks; export buttons (JSON, HTML, Markdown). A notice
  states that results are not stored and expire after the TTL, so export anything you want to keep.
- **No history page.** Nothing is persisted, so there is nothing to list.
- Web scans run in a background thread (no Celery/Redis) with the page polling for progress.
  The runner is independent of Django, so a task queue can be added later if needed.

### Theme hook
Templates extend a single `base.html`. Default skin: Bootstrap 5 (MIT, vendored). If
`web/static/theme/dashlite/` exists (git-ignored, populated by the operator from their **original,
unmodified** DashLite download) and `THEME=dashlite` is set, the base template switches to a DashLite
skin. Page content blocks are shared. DashLite files are **never committed** to the repo (commercial
ThemeForest licence; no redistribution), and the operator's customised EPGLUM/OTP copies are not used.

## 7. Export

All formats are generated from the same `ScanReport`:
- **JSON** — machine-readable source of truth.
- **HTML** — single self-contained file (inline CSS, no external dependencies).
- **Markdown** — for tickets and docs.

## 8. Testing

- Each check is tested against a local HTTP server serving deliberately good and bad configurations.
- Tests for the SSRF guard (including redirect hops), runner resilience (crashing/timing-out check),
  and exporters (snapshot tests).
- The test suite never touches the internet.

## 9. Packaging and docs

- `pipx install` for the CLI; `Dockerfile` for the web app.
- README: install, usage, check list, safety defaults, an explicit "only scan what you are authorised
  to test" section, and the no-auth / do-not-expose-publicly warning.
- `CONTRIBUTING.md` with a "how to add a check" walkthrough; `SECURITY.md`; MIT `LICENSE`.

## 10. Roadmap (separate specs)

- **v2:** opt-in active checks (reflected XSS/injection probes, form discovery, small wordlist) behind
  an ownership check (DNS TXT record or `/.well-known/` file).
- **Later:** known-CVE/outdated-library detection, scheduled scans with history and diffs, CI
  integration, PDF export.
