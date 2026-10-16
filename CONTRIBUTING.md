# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Tests never touch the internet: use the local `server` fixture (`tests/fake_server.py`), `httpx.MockTransport`, and the `fake_dns` fixture.

### Site (end-to-end) tests

`e2e/` drives the real app (gunicorn, collectstatic, WhiteNoise) in a browser, scans the running site with siteward itself, and builds the Docker image to check what it serves. They are not part of the default `pytest` run:

```bash
pip install -e '.[dev,e2e]' && playwright install chromium
pytest e2e          # Docker tests skip themselves if docker is not installed
```

Any console error, JS error or failed request fails a browser test. Mark a test `@pytest.mark.expects_http_error` if it deliberately provokes a 4xx page.

What lives there: the scan flow and exports, the logo and static files, public mode with Cloudflare's Turnstile test keys (needs internet), accessibility (axe-core, WCAG 2.1 AA), no horizontal scroll from 320px to desktop, a light load test, the site scanning itself, and the Docker image.

### Checking a deployed site

```bash
python scripts/smoke_deployed.py https://scan.example.com --public
```

Checks the page, security headers, static files, error pages, the HTTP to HTTPS redirect, certificate expiry (`--min-cert-days`) and a self-scan, and exits 1 on any failure. `.github/workflows/monitor.yml` runs it daily against the repository variable `SITE_URL`, which doubles as uptime and certificate monitoring.

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
