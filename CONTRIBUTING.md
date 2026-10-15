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
