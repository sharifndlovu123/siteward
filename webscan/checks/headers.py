import re

from webscan.core.models import Finding

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
