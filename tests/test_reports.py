import json

import pytest

from siteward.reports import FORMATS, render, to_html, to_json, to_markdown


def test_json_roundtrips(sample_report):
    data = json.loads(to_json(sample_report))
    assert data["target"] == "http://example.com/" and data["grade"] == "C" and data["incomplete"] is True


def test_markdown_lists_findings_passed_skipped_and_errors(sample_report):
    md = to_markdown(sample_report)
    assert md.startswith("# Security scan")
    assert "CSP missing" in md and "Add a CSP" in md
    assert "cookies.flags" in md  # passed check is listed
    assert "target is not served over HTTPS" in md  # skipped reason
    assert "TimeoutError: lookup" in md  # errored check is never hidden


def test_markdown_neutralises_hostile_content(sample_report):
    md = to_markdown(sample_report)
    # the title is outside a code fence, so markup characters must be backslash-escaped
    assert "X-Powered-By: \\<script\\>alert(1)\\</script\\>" in md
    # evidence containing a ``` run must be fenced with a longer fence so it cannot break out
    assert "````" in md


def test_html_escapes_hostile_content(sample_report):
    html = to_html(sample_report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_is_self_contained(sample_report):
    html = to_html(sample_report)
    for banned in ("<link", "src=", "@import", "http://cdn", "https://cdn"):
        assert banned not in html
    assert "<style>" in html and "CSP missing" in html


def test_render_dispatch_and_formats(sample_report):
    assert set(FORMATS) == {"json", "md", "html"}
    assert render(sample_report, "json") == to_json(sample_report)
    with pytest.raises(KeyError):
        render(sample_report, "pdf")
