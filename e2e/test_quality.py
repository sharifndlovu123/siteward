"""Accessibility (axe-core) and responsive layout on every kind of page the site serves."""
import json
from pathlib import Path

import axe_playwright_python
import pytest
from playwright.sync_api import expect

AXE = (Path(axe_playwright_python.__file__).parent / "axe.min.js").read_text()
WIDTHS = {"phone-320": (320, 640), "phone-375": (375, 667), "tablet-768": (768, 1024), "desktop-1280": (1280, 800)}


@pytest.fixture(scope="module")
def browser_context_args(browser_context_args):
    # axe is injected as an inline script; the CSP itself is covered by the other e2e tests
    return {**browser_context_args, "bypass_csp": True}


def finished_scan(page, base, target):
    page.goto(base + "/")
    page.fill("#url", target.url)
    page.check("#authorised")
    page.click("button[type=submit]")
    expect(page.locator("text=Export JSON")).to_be_visible(timeout=60_000)


def pages(page, live_site, target):
    """Yield (name, url) for each kind of page."""
    finished_scan(page, live_site, target)
    yield "results", page.url
    yield "index", live_site + "/"
    yield "policy", live_site + "/policy/"
    yield "expired", live_site + "/scan/doesnotexist/"


def axe_violations(page):
    page.evaluate(AXE)
    result = page.evaluate("axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice']}})")
    return [f"{v['id']} ({v['impact']}): {v['help']} -> {[n['target'] for n in v['nodes']][:3]}" for v in result["violations"]]


@pytest.mark.expects_http_error
def test_no_accessibility_violations_on_any_page(page, live_site, target):
    failures = {}
    for name, url in pages(page, live_site, target):
        page.goto(url)
        found = axe_violations(page)
        if found:
            failures[name] = found
    assert not failures, json.dumps(failures, indent=2)


@pytest.mark.expects_http_error
@pytest.mark.parametrize("size", WIDTHS.values(), ids=WIDTHS.keys())
def test_no_horizontal_scroll_at_any_width(page, live_site, target, size):
    page.set_viewport_size({"width": size[0], "height": size[1]})
    overflowing = {}
    for name, url in pages(page, live_site, target):
        page.goto(url)
        scroll, client = page.evaluate("[document.documentElement.scrollWidth, document.documentElement.clientWidth]")
        if scroll > client:
            overflowing[name] = f"{scroll}px content in a {client}px viewport"
    assert not overflowing, overflowing


def test_form_is_usable_by_keyboard_alone(page, live_site, target):
    page.goto(live_site + "/")
    page.locator("#url").focus()
    page.keyboard.type(target.url)
    page.keyboard.press("Tab")
    page.keyboard.press("Space")  # the authorisation checkbox
    expect(page.locator("#authorised")).to_be_checked()
    page.keyboard.press("Enter")
    expect(page).to_have_url(__import__("re").compile(r"/scan/"))


def test_every_form_control_has_an_accessible_name(page, live_site):
    page.goto(live_site + "/")
    for control in page.locator("input:not([type=hidden]), select, textarea").all():
        assert control.evaluate("el => el.labels && el.labels.length > 0"), control.get_attribute("id")
