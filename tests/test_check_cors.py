from siteward.checks import cors


def test_reflected_origin_with_credentials_is_high(server, ctx_for):
    server.add("/", "<html></html>", headers=[
        ("Access-Control-Allow-Origin", cors.PROBE_ORIGIN), ("Access-Control-Allow-Credentials", "true")])
    found = cors.run(ctx_for(server))
    assert [(f.id, f.severity) for f in found] == [("cors.reflected-origin", "high")]


def test_reflected_origin_without_credentials_is_medium(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Access-Control-Allow-Origin", cors.PROBE_ORIGIN)])
    assert [(f.id, f.severity) for f in cors.run(ctx_for(server))] == [("cors.reflected-origin", "medium")]


def test_wildcard_is_informational(server, ctx_for):
    server.add("/", "<html></html>", headers=[("Access-Control-Allow-Origin", "*")])
    assert [(f.id, f.severity) for f in cors.run(ctx_for(server))] == [("cors.wildcard", "info")]


def test_no_cors_headers_is_clean(server, ctx_for):
    assert cors.run(ctx_for(server)) == []


def test_probe_sends_origin_header(server, ctx_for):
    cors.run(ctx_for(server))
    assert any(h.get("Origin") == cors.PROBE_ORIGIN for _, _, h in server.requests)
