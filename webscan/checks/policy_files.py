import re

from webscan.core.models import Finding

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
