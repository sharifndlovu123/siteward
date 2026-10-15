from webscan.core.models import Finding

ID = "cors.policy"
CATEGORY = "CORS"
OPT_IN = None
PROBE_ORIGIN = "https://webscan-cors-probe.example"


def run(ctx):
    fetch = ctx.client.get(ctx.target.url, headers={"Origin": PROBE_ORIGIN})
    allow = fetch.headers.get("access-control-allow-origin")
    credentials = (fetch.headers.get("access-control-allow-credentials") or "").lower() == "true"
    evidence = f"Access-Control-Allow-Origin: {allow}; Allow-Credentials: {credentials}"
    if allow == PROBE_ORIGIN:
        severity = "high" if credentials else "medium"
        return [Finding("cors.reflected-origin", "CORS reflects arbitrary Origin", CATEGORY, severity, evidence,
                        "Allow only an explicit list of trusted origins.")]
    if allow == "null" and credentials:
        return [Finding("cors.null-origin", "CORS allows the 'null' origin with credentials", CATEGORY, "high",
                        evidence, "Never allow the null origin with credentials.")]
    if allow == "*":
        return [Finding("cors.wildcard", "CORS allows any origin (*)", CATEGORY, "info", evidence,
                        "Fine for public static content; restrict it if the responses are sensitive.")]
    return []
