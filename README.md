<p align="center"><img src="docs/assets/logo.svg" alt="siteward" height="64"></p>

# siteward

A small, self-hostable **passive** web security scanner. Give it a URL, it runs a set of standard checks and shows you the findings; export them as JSON, Markdown, or a self-contained HTML file. **Nothing about scanned sites is stored.**

> [!IMPORTANT]
> **Only use siteward on websites you run yourself, or where you have explicit authority to test.**
> It exists to help developers find gaps in the sites they are building or managing, and to find them sooner. Running it against a service you have no permission to test is your own action, and you alone are responsible for it and any consequences. The authors and contributors accept no liability for misuse.
>
> siteward is a routine-coverage tool; it does not replace a manual penetration test.

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

MIT licensed. See `CONTRIBUTING.md` to add a check and `SECURITY.md` to report a vulnerability.
