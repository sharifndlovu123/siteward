"""Public mode in a real browser, with Cloudflare's documented Turnstile test keys (needs internet).

https://developers.cloudflare.com/turnstile/troubleshooting/testing/
"""
import urllib.request

import pytest
from playwright.sync_api import expect

SITE_KEY_PASS = "1x00000000000000000000AA"      # widget auto-solves
SECRET_PASS = "1x0000000000000000000000000000000AA"  # siteverify always succeeds
SECRET_FAIL = "2x0000000000000000000000000000000AA"  # siteverify always fails


def _cloudflare_reachable():
    try:
        urllib.request.urlopen("https://challenges.cloudflare.com/turnstile/v0/api.js", timeout=5)
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _cloudflare_reachable(), reason="cannot reach challenges.cloudflare.com")


@pytest.fixture(scope="module")
def public_site(start_site, tmp_path_factory):
    return start_site(PUBLIC_MODE="1", TURNSTILE_SITE_KEY=SITE_KEY_PASS, TURNSTILE_SECRET=SECRET_PASS,
                      ABUSE_LOG_KEY="e2e", ABUSE_LOG_DIR=str(tmp_path_factory.mktemp("abuse")),
                      ALLOW_PRIVATE_TARGETS="0")


@pytest.fixture(scope="module")
def failing_site(start_site, tmp_path_factory):
    return start_site(PUBLIC_MODE="1", TURNSTILE_SITE_KEY=SITE_KEY_PASS, TURNSTILE_SECRET=SECRET_FAIL,
                      ABUSE_LOG_KEY="e2e", ABUSE_LOG_DIR=str(tmp_path_factory.mktemp("abuse")))


def submit(page, base, url="http://127.0.0.1:1"):
    page.goto(base + "/")
    page.fill("#url", url)
    page.check("#authorised")
    # the widget solves itself and writes its token into a hidden input
    expect(page.locator("[name=cf-turnstile-response]")).not_to_have_value("", timeout=30_000)
    page.click("button[type=submit]")


def test_turnstile_widget_loads_under_the_csp_and_hides_the_port_check(page, public_site):
    page.goto(public_site + "/")
    expect(page.locator(".cf-turnstile")).to_be_attached()
    # the widget's iframe sits in a closed shadow root, so prove it ran by the token it writes back
    expect(page.locator("[name=cf-turnstile-response]")).not_to_have_value("", timeout=30_000)
    expect(page.locator("#ports")).to_have_count(0)  # port scanning is forced off in public mode
    # no CSP violation: the `page` fixture fails on any console error, and CSP violations are console errors


@pytest.mark.expects_http_error
def test_a_passed_challenge_reaches_target_validation(page, public_site):
    submit(page, public_site)  # loopback is refused in public mode, which proves the challenge itself was accepted
    expect(page.locator("[role=alert]")).to_contain_text("Cannot scan that target")
    assert "Verification failed" not in page.content()


@pytest.mark.expects_http_error
def test_a_failed_challenge_is_reported_and_blocks_the_scan(page, failing_site):
    submit(page, failing_site)
    expect(page.locator("[role=alert]")).to_contain_text("Verification failed")
    assert "/scan/" not in page.url
