from siteward.checks import cookies


def test_session_cookie_without_flags(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "sessionid=SECRET123; Path=/")])
    found = cookies.run(ctx_for(server))
    by_id = {f.id: f for f in found}
    assert by_id["cookies.httponly"].severity == "medium"  # session-looking name
    assert "cookies.samesite" in by_id
    assert "cookies.secure" not in by_id  # plain-http target: Secure not expected
    assert all("SECRET123" not in f.evidence for f in found)  # never echo cookie values


def test_well_configured_cookie_is_clean(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "pref=1; Secure; HttpOnly; SameSite=Lax")])
    assert cookies.run(ctx_for(server)) == []


def test_samesite_none_requires_secure(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Set-Cookie", "a=1; HttpOnly; SameSite=None")])
    assert any(f.id == "cookies.secure" and f.severity == "medium" for f in cookies.run(ctx_for(server)))


def test_no_cookies_no_findings(server, ctx_for):
    assert cookies.run(ctx_for(server)) == []
