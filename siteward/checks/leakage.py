import re

from siteward.core.models import Finding

ID = "leakage.banner"
CATEGORY = "Information leakage"
OPT_IN = None
PROBE_PATH = "/siteward-not-found-probe"
_VERSIONED = re.compile(r"\d+\.\d+")
_TRACE_MARKERS = ("Traceback (most recent call last)", "Stack trace:", "at java.", "Fatal error:", "SQLSTATE[",
                  "Exception in thread", "Whoops! There was an error")


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
    # Only an error status counts: a 200 "not found" page that happens to contain scary words is a soft 404.
    if probe.status >= 400 and any(marker in probe.text for marker in _TRACE_MARKERS):
        out.append(Finding("leakage.verbose-errors", "Error page exposes a stack trace", CATEGORY, "medium",
                           f"GET {PROBE_PATH} -> {probe.status} with debug output",
                           "Disable debug/verbose error output in production."))
    return out
