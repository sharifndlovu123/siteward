import json
from datetime import datetime, timezone

import pytest

from siteward.core.models import CheckResult, Finding, ScanReport, severity_rank

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def finding(sev, fid="x"):
    return Finding(fid, f"title {fid}", "Cat", sev, "evidence", "fix")


def report(results):
    return ScanReport("http://example.com/", NOW, NOW, "0.1.0", {"ports": False}, results)


def test_unknown_severity_rejected():
    with pytest.raises(ValueError):
        finding("urgent")


def test_severity_rank_orders():
    assert severity_rank("info") < severity_rank("low") < severity_rank("critical")


def test_findings_sorted_most_severe_first():
    r = report([CheckResult("a", "C", "findings", [finding("low", "1"), finding("high", "2"), finding("medium", "3")])])
    assert [f.severity for f in r.findings] == ["high", "medium", "low"]


def test_counts_include_all_severities():
    r = report([CheckResult("a", "C", "findings", [finding("low"), finding("low")])])
    assert r.counts == {"info": 0, "low": 2, "medium": 0, "high": 0, "critical": 0}


@pytest.mark.parametrize(
    "severities,grade",
    [([], "A"), (["info"], "A"), (["low"], "B"), (["low", "medium"], "C"), (["high"], "D"), (["medium", "critical"], "F")],
)
def test_grade_is_driven_by_worst_finding(severities, grade):
    r = report([CheckResult("a", "C", "findings", [finding(s) for s in severities])])
    assert r.grade == grade


def test_incomplete_when_a_check_errored():
    ok = report([CheckResult("a", "C", "passed")])
    bad = report([CheckResult("a", "C", "error", message="boom")])
    assert ok.incomplete is False and bad.incomplete is True


def test_to_dict_is_json_serialisable():
    r = report([CheckResult("a", "C", "findings", [finding("low")]), CheckResult("b", "C", "skipped", message="n/a")])
    data = json.loads(json.dumps(r.to_dict()))
    assert data["grade"] == "B"
    assert data["results"][0]["findings"][0]["severity"] == "low"
    assert data["started"].startswith("2026-10-15")
