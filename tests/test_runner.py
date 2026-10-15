import socket
import time
from types import SimpleNamespace as NS

import pytest

from webscan.core.models import Finding, Skip
from webscan.core.netguard import BlockedTarget
from webscan.core.runner import ScanError, run_scan

OPTS = {"allow_private": True, "min_interval": 0}


def check(check_id, fn, opt_in=None):
    return NS(ID=check_id, CATEGORY="T", OPT_IN=opt_in, run=fn)


def finding():
    return Finding("t.f", "A finding", "T", "low", "ev", "fix")


def by_id(report):
    return {r.check_id: r for r in report.results}


def test_statuses_for_pass_findings_skip_and_crash(server):
    def crash(ctx):
        raise RuntimeError("boom")

    def skip(ctx):
        raise Skip("not applicable")

    checks = [
        check("a.pass", lambda ctx: []),
        check("b.find", lambda ctx: [finding()]),
        check("c.skip", skip),
        check("d.crash", crash),
    ]
    report = run_scan(server.url, OPTS, checks=checks)
    results = by_id(report)
    assert results["a.pass"].status == "passed"
    assert results["b.find"].status == "findings" and len(results["b.find"].findings) == 1
    assert results["c.skip"].status == "skipped" and "not applicable" in results["c.skip"].message
    assert results["d.crash"].status == "error" and "RuntimeError" in results["d.crash"].message
    assert report.incomplete is True


def test_opt_in_check_skipped_unless_enabled(server):
    calls = []
    opt = check("p.ports", lambda ctx: calls.append(1) or [], opt_in="ports")
    off = run_scan(server.url, OPTS, checks=[opt])
    assert by_id(off)["p.ports"].status == "skipped" and calls == []
    on = run_scan(server.url, {**OPTS, "ports": True}, checks=[opt])
    assert by_id(on)["p.ports"].status == "passed" and calls == [1]


def test_hanging_check_times_out_without_blocking_the_scan(server):
    checks = [check("a.fast", lambda ctx: []), check("b.hang", lambda ctx: time.sleep(2) or [])]
    start = time.monotonic()
    report = run_scan(server.url, OPTS, checks=checks, timeout=0.3)
    assert time.monotonic() - start < 1.5
    results = by_id(report)
    assert results["a.fast"].status == "passed"
    assert results["b.hang"].status == "error" and "timed out" in results["b.hang"].message


def test_on_result_called_once_per_check(server):
    seen = []
    checks = [check("a", lambda ctx: []), check("b", lambda ctx: [finding()])]
    run_scan(server.url, OPTS, on_result=seen.append, checks=checks)
    assert sorted(r.check_id for r in seen) == ["a", "b"]


def test_report_metadata_and_public_options(server):
    report = run_scan(server.url, {**OPTS, "ports": True}, checks=[check("a", lambda ctx: [])])
    assert report.target == server.url + "/"
    assert report.options == {"ports": True}
    assert report.started <= report.finished and report.version


def test_unreachable_target_raises_scan_error():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here now
    with pytest.raises(ScanError):
        run_scan(f"http://127.0.0.1:{port}", OPTS, checks=[])


def test_private_target_refused_without_allow_private(server):
    with pytest.raises(BlockedTarget):
        run_scan(server.url, {"min_interval": 0}, checks=[])


def test_all_builtin_checks_are_discovered():
    from webscan.core.runner import discover_checks

    ids = {m.ID for m in discover_checks()}
    assert ids >= {
        "headers.security", "cookies.flags", "cors.policy", "leakage.banner", "transport.https-redirect",
        "policy.files", "exposure.files", "tls.certificate", "dns.email", "dns.takeover", "ports.common",
    }
