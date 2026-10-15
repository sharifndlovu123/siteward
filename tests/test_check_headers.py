from siteward.checks import headers

GOOD = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "geolocation=()"),
]


def ids(findings):
    return {f.id for f in findings}


def test_good_headers_have_no_findings(server, ctx_for):
    server.add("/", "<html></html>", headers=GOOD)
    assert headers.run(ctx_for(server)) == []


def test_missing_headers_are_reported(server, ctx_for):
    assert ids(headers.run(ctx_for(server))) >= {
        "headers.csp", "headers.nosniff", "headers.framing", "headers.referrer", "headers.permissions"
    }


def test_hsts_is_only_expected_on_https(server, ctx_for):
    assert "headers.hsts" not in ids(headers.run(ctx_for(server)))  # fake server is plain http


def test_weak_csp_is_flagged_with_evidence(server, ctx_for):
    weak = [("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")] + GOOD[1:]
    server.add("/", "<html></html>", headers=weak)
    found = headers.run(ctx_for(server))
    assert ids(found) == {"headers.csp-weak"}
    assert "unsafe-inline" in found[0].evidence
