import re

import pytest
from playwright.sync_api import expect


def run_scan(page, base, url):
    page.goto(base + "/")
    page.fill("#url", url)
    page.check("#authorised")
    page.click("button[type=submit]")


def test_scan_flow_polls_and_renders_results(page, live_site, target):
    run_scan(page, live_site, target.url)
    expect(page).to_have_url(re.compile(r"/scan/[^/]+/$"))
    expect(page.locator("text=Grade")).to_be_visible(timeout=60_000)  # poll.js swapped in the finished view
    expect(page.locator("h2", has_text="Findings")).to_be_visible()
    assert page.locator("details summary .badge").count() > 0  # the bare fake server has findings


def test_exports_download(page, live_site, target):
    run_scan(page, live_site, target.url)
    expect(page.locator("text=Export JSON")).to_be_visible(timeout=60_000)
    for label, ext in (("Export JSON", "json"), ("Export Markdown", "md"), ("Export HTML", "html")):
        with page.expect_download() as d:
            page.click(f"text={label}")
        assert d.value.suggested_filename == f"siteward-report.{ext}"


def test_hostile_banner_is_escaped_in_the_page(page, live_site, target):
    target.banner = "<img src=x onerror=alert(1)>"
    run_scan(page, live_site, target.url)
    expect(page.locator("text=Grade")).to_be_visible(timeout=60_000)
    assert page.locator("details img").count() == 0  # rendered as text, never as markup


def test_nav_logo_and_favicon_load(page, live_site):
    page.goto(live_site + "/")
    logo = page.locator("nav img[src*='logo-mark']")
    expect(logo).to_be_visible()
    assert logo.evaluate("i => i.naturalWidth") > 0
    assert page.locator("link[rel=icon]").get_attribute("href").endswith("favicon.svg")
    assert page.request.get(live_site + "/static/img/favicon.svg").ok


def test_static_assets_served_by_whitenoise(page, live_site):
    for path in ("/static/vendor/bootstrap.min.css", "/static/js/poll.js", "/static/img/logo-mark.svg"):
        assert page.request.get(live_site + path).ok, path


@pytest.mark.expects_http_error
def test_unchecked_authorisation_is_refused(page, live_site, target):
    page.goto(live_site + "/")
    page.fill("#url", target.url)
    page.click("button[type=submit]")
    expect(page.locator("[role=alert]")).to_contain_text("authorised")


@pytest.mark.expects_http_error
def test_unknown_scan_shows_expired_message(page, live_site):
    page.goto(live_site + "/scan/doesnotexist/")
    expect(page.locator(".alert-warning")).to_contain_text("expired")
