from siteward.checks import leakage


def ids(findings):
    return {f.id for f in findings}


def test_clean_server(server, ctx_for):
    assert leakage.run(ctx_for(server)) == []


def test_server_version_and_powered_by(server, ctx_for):
    server.banner = "Apache/2.4.41"
    server.add("/", "<html></html>", headers=[("X-Powered-By", "PHP/7.4.3")])
    found = leakage.run(ctx_for(server))
    assert ids(found) == {"leakage.server-version", "leakage.x-powered-by"}
    assert any("Apache/2.4.41" in f.evidence for f in found)


def test_verbose_error_page(server, ctx_for):
    server.add(leakage.PROBE_PATH, "Traceback (most recent call last):\n  File x", status=500)
    assert ids(leakage.run(ctx_for(server))) == {"leakage.verbose-errors"}
