import re

from siteward.core.models import Finding

ID = "cookies.flags"
CATEGORY = "Cookies"
OPT_IN = None
_SENSITIVE = re.compile(r"sess|token|auth|jwt|sid|login", re.I)


def run(ctx):
    https = ctx.final.scheme == "https"
    out = []
    for raw in ctx.baseline.headers.get_list("set-cookie"):
        first = raw.split(";")[0]
        # RFC 6265: a cookie without '=' has an empty name and the text is its VALUE: never echo it
        name = first.split("=", 1)[0].strip() if "=" in first else "(unnamed)"
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
