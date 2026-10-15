import ipaddress
import re

import dns.exception
import dns.resolver

from webscan.core.models import Finding, Skip

ID = "dns.email"
CATEGORY = "DNS / Email"
OPT_IN = None
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail")


def _txt(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except dns.exception.DNSException:
        return []
    return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in answers]


def assess(spf, dmarc, dkim_found):
    out = []

    def add(slug, title, severity, evidence, fix):
        out.append(Finding(f"dns.{slug}", title, CATEGORY, severity, evidence, fix))

    if not spf:
        add("no-spf", "No SPF record", "medium", "no TXT record starting with v=spf1",
            "Publish an SPF record, e.g. 'v=spf1 -all' if the domain sends no mail.")
    elif len(spf) > 1:
        add("spf-multiple", "Multiple SPF records (invalid)", "medium", " | ".join(spf), "Merge into a single SPF record.")
    elif "+all" in spf[0] or "?all" in spf[0]:
        add("spf-permissive", "SPF allows any sender", "high" if "+all" in spf[0] else "low", spf[0],
            "End the SPF record with '-all' (or '~all').")

    if not dmarc:
        add("no-dmarc", "No DMARC record", "medium", "no TXT record at _dmarc",
            "Publish a DMARC record with p=quarantine or p=reject.")
    else:
        match = re.search(r"\bp=(\w+)", dmarc[0])
        if match and match.group(1).lower() == "none":
            add("dmarc-none", "DMARC policy is monitor-only (p=none)", "low", dmarc[0],
                "Move to p=quarantine or p=reject once reports look clean.")

    if not dkim_found:
        add("dkim-not-found", "No DKIM key found on common selectors", "info",
            f"checked: {', '.join(DKIM_SELECTORS)}",
            "Informational: DKIM selectors cannot be enumerated. Ignore if your mail provider uses a custom selector.")
    return out


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _candidates(host):
    host = host.removeprefix("www.")
    labels = host.split(".")
    return [host] + ([".".join(labels[1:])] if len(labels) > 2 else [])


def run(ctx):
    host = ctx.target.host
    if _is_ip(host):
        raise Skip("target is an IP address; no mail DNS to check")
    domain = _candidates(host)[0]
    spf = dmarc = []
    for candidate in _candidates(host):
        spf = [r for r in _txt(candidate) if r.lower().startswith("v=spf1")]
        dmarc = [r for r in _txt(f"_dmarc.{candidate}") if r.lower().startswith("v=dmarc1")]
        if spf or dmarc:
            domain = candidate
            break
    dkim_found = any(_txt(f"{sel}._domainkey.{domain}") for sel in DKIM_SELECTORS)
    return assess(spf, dmarc, dkim_found)
