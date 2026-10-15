from webscan.core.models import Finding
from webscan.core.netguard import FetchError

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
