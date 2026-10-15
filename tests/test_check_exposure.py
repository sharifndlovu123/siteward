from siteward.checks import exposure


def ids(findings):
    return {f.id for f in findings}


def test_clean_site_has_no_findings(server, ctx_for):
    assert exposure.run(ctx_for(server)) == []


def test_soft_404_site_does_not_produce_false_positives(server, ctx_for):
    server.set_default("<html><body>Welcome home</body></html>", headers=[("Content-Type", "text/html")])
    assert exposure.run(ctx_for(server)) == []


def test_exposed_git_and_env_are_found_without_leaking_secrets(server, ctx_for):
    server.add("/.git/HEAD", "ref: refs/heads/main\n")
    server.add("/.env", "DB_PASSWORD=hunter2\nAPI_KEY=abc123\n")
    found = exposure.run(ctx_for(server))
    assert ids(found) == {"exposure.git", "exposure.env"}
    assert all(f.severity == "high" for f in found)
    blob = " ".join(f.evidence + f.title + f.remediation for f in found)
    assert "hunter2" not in blob and "abc123" not in blob


def test_sql_dump_and_phpinfo(server, ctx_for):
    server.add("/backup.sql", "CREATE TABLE users (id int);")
    server.add("/phpinfo.php", "<title>phpinfo()</title>")
    assert ids(exposure.run(ctx_for(server))) == {"exposure.sql-dump", "exposure.phpinfo"}


def test_directory_listing_on_homepage(server, ctx_for):
    server.add("/", "<html><title>Index of /</title></html>", headers=[("Content-Type", "text/html")])
    assert "exposure.directory-listing" in ids(exposure.run(ctx_for(server)))
