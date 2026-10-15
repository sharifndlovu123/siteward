from types import SimpleNamespace as NS

import pytest

from siteward.checks import dns_email
from siteward.core.models import Skip


def ids(findings):
    return {f.id for f in findings}


def test_well_configured_domain():
    spf = ["v=spf1 include:_spf.google.com -all"]
    dmarc = ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
    assert dns_email.assess(spf, dmarc, dkim_found=True) == []


def test_nothing_configured():
    found = dns_email.assess([], [], dkim_found=False)
    assert {"dns.no-spf", "dns.no-dmarc", "dns.dkim-not-found"} <= ids(found)


def test_permissive_spf_and_monitor_only_dmarc():
    found = dns_email.assess(["v=spf1 +all"], ["v=DMARC1; p=none"], dkim_found=True)
    assert ids(found) == {"dns.spf-permissive", "dns.dmarc-none"}


def test_multiple_spf_records_are_invalid():
    found = dns_email.assess(["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=reject"], dkim_found=True)
    assert ids(found) == {"dns.spf-multiple"}


def test_run_uses_dns_lookups(monkeypatch):
    answers = {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]}
    monkeypatch.setattr(dns_email, "_txt", lambda name: answers.get(name, []))
    found = dns_email.run(NS(target=NS(host="example.com")))
    assert ids(found) == {"dns.dkim-not-found"}  # only the informational DKIM note remains


def test_ip_targets_are_skipped():
    with pytest.raises(Skip):
        dns_email.run(NS(target=NS(host="93.184.216.34")))
