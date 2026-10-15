from webscan.checks import policy_files


def ids(findings):
    return {f.id for f in findings}


def test_missing_security_txt_is_informational(server, ctx_for):
    found = policy_files.run(ctx_for(server))
    assert ids(found) == {"policy.no-security-txt"} and found[0].severity == "info"


def test_valid_security_txt_passes(server, ctx_for):
    server.add("/.well-known/security.txt", "Contact: mailto:security@example.com\n")
    assert policy_files.run(ctx_for(server)) == []


def test_soft_404_site_does_not_fake_a_security_txt(server, ctx_for):
    server.set_default("<html>home</html>", headers=[("Content-Type", "text/html")])
    assert ids(policy_files.run(ctx_for(server))) == {"policy.no-security-txt"}  # no "Contact:" -> still missing


def test_robots_listing_sensitive_paths(server, ctx_for):
    server.add("/.well-known/security.txt", "Contact: mailto:a@b.co\n")
    server.add("/robots.txt", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /blog/\n")
    found = policy_files.run(ctx_for(server))
    assert ids(found) == {"policy.robots-sensitive"}
    assert "/admin/" in found[0].evidence and "/blog/" not in found[0].evidence
