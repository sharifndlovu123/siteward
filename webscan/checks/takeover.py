import ipaddress

import dns.exception
import dns.resolver

from webscan.core.models import Finding, Skip

ID = "dns.takeover"
CATEGORY = "DNS / Email"
OPT_IN = None

# CNAME suffix -> text shown by the provider for an unclaimed resource
PROVIDERS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "Web app not found",
    "surge.sh": "project not found",
}


def _cname(name):
    try:
        answers = dns.resolver.resolve(name, "CNAME", lifetime=5)
    except dns.exception.DNSException:
        return None
    return str(answers[0].target).rstrip(".").lower()


def _exists(name):
    try:
        dns.resolver.resolve(name, "A", lifetime=5)
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.DNSException:
        return True  # unsure: do not raise a false alarm
    return True


def run(ctx):
    host = ctx.target.host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise Skip("target is an IP address")
    target = _cname(host)
    if not target:
        return []
    if not _exists(target):
        return [Finding("takeover.dangling-cname", "CNAME points at a name that does not resolve", CATEGORY, "high",
                        f"{host} -> {target} (NXDOMAIN)",
                        "Remove the stale CNAME or re-claim the target resource.")]
    for suffix, fingerprint in PROVIDERS.items():
        if target.endswith(suffix) and fingerprint in ctx.baseline.text:
            return [Finding("takeover.unclaimed-service", "CNAME points at an unclaimed third-party resource",
                            CATEGORY, "high", f"{host} -> {target}; provider 'not found' page served",
                            "Re-claim the resource or remove the DNS record.")]
    return []
