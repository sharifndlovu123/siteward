"""siteward scans its own running instance and must not find anything serious."""
from siteward.core.runner import run_scan

# The test instance speaks plain HTTP; in production TLS terminates at Cloudflare.
ACCEPTED = {"transport.no-https-redirect"}


def test_own_site_has_no_serious_findings(live_site):
    report = run_scan(live_site, {"allow_private": True, "min_interval": 0})
    serious = [f"{f.severity}: {f.title}" for f in report.findings
               if f.severity in ("critical", "high", "medium") and f.id not in ACCEPTED]
    assert not serious, "\n".join(serious)
