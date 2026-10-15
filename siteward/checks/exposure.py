import re

from siteward.core.models import Finding
from siteward.core.netguard import FetchError

ID = "exposure.files"
CATEGORY = "Exposed files"
OPT_IN = None


def _git(body):
    return body.startswith(b"ref:") or b"[core]" in body


def _env(body):
    return re.search(rb"^[A-Z][A-Z0-9_]*=.+$", body, re.M) is not None


def _sql(body):
    return b"CREATE TABLE" in body or b"INSERT INTO" in body


def _zip(body):
    return body.startswith(b"PK\x03\x04")


# (path, slug, validator, severity, title, fix). Validators look at CONTENT, so a site that
# answers 200 to every path (soft 404) produces no false positives.
PROBES = [
    ("/.git/HEAD", "git", _git, "high", "Git repository is publicly accessible",
     "Block access to /.git and remove it from the web root."),
    ("/.git/config", "git", _git, "high", "Git repository is publicly accessible",
     "Block access to /.git and remove it from the web root."),
    ("/.env", "env", _env, "high", "Environment file (.env) is publicly accessible",
     "Remove .env from the web root and rotate any secrets it contained."),
    ("/wp-config.php.bak", "config-backup", lambda b: b"DB_PASSWORD" in b, "high",
     "Configuration backup is publicly accessible", "Delete backup files from the web root and rotate credentials."),
    ("/config.php.bak", "config-backup", lambda b: b"<?php" in b, "high",
     "Configuration backup is publicly accessible", "Delete backup files from the web root and rotate credentials."),
    ("/backup.sql", "sql-dump", _sql, "high", "Database dump is publicly accessible",
     "Remove database dumps from the web root."),
    ("/dump.sql", "sql-dump", _sql, "high", "Database dump is publicly accessible",
     "Remove database dumps from the web root."),
    ("/backup.zip", "archive", _zip, "high", "Backup archive is publicly accessible",
     "Remove archives from the web root."),
    ("/.DS_Store", "ds-store", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"), "low",
     ".DS_Store file reveals directory contents", "Delete .DS_Store files from deployments."),
    ("/phpinfo.php", "phpinfo", lambda b: b"phpinfo()" in b, "medium", "phpinfo() page is publicly accessible",
     "Remove phpinfo pages from production."),
    ("/server-status", "server-status", lambda b: b"Apache Server Status" in b, "medium",
     "Apache server-status page is publicly accessible", "Restrict /server-status to localhost."),
]
_LISTING_DIRS = ("/uploads/", "/backup/", "/files/")


_HTML_OK = {"phpinfo", "server-status"}  # these legitimately are HTML pages
SOFT_404_PROBE = "/siteward-soft404-probe"


def _is_html(fetch):
    return fetch.headers.get("content-type", "").lower().startswith("text/html")


def run(ctx):
    base = ctx.target.url.rstrip("/")
    out, seen = [], set()

    # Soft-404 guard: a site that answers 200 to unknown paths (or redirects them to its homepage)
    # must not make its own error/home page look like an exposed file.
    soft_bodies = {ctx.baseline.body}
    probe_body = None
    try:
        probe = ctx.client.get(base + SOFT_404_PROBE)
        if probe.status == 200:
            probe_body = probe.body
            soft_bodies.add(probe.body)
    except FetchError:
        pass

    for path, slug, valid, severity, title, fix in PROBES:
        if slug in seen:
            continue
        try:
            fetch = ctx.client.get(base + path)
        except FetchError:
            continue
        if fetch.body in soft_bodies or (_is_html(fetch) and slug not in _HTML_OK):
            continue
        if fetch.status == 200 and valid(fetch.body):
            seen.add(slug)
            # Evidence names the path only; file contents (secrets) are never copied into the report.
            out.append(Finding(f"exposure.{slug}", title, CATEGORY, severity,
                               f"GET {path} returned 200 ({len(fetch.body)} bytes); content not reproduced", fix))

    pages = [("/", ctx.baseline)]
    for directory in _LISTING_DIRS:
        try:
            pages.append((directory, ctx.client.get(base + directory)))
        except FetchError:
            continue
    for path, fetch in pages:
        if path != "/" and probe_body is not None and fetch.body == probe_body:
            continue  # same page as an unknown path: a soft 404, not a listing
        if fetch.status == 200 and re.search(r"<title>\s*Index of /", fetch.text, re.I):
            out.append(Finding("exposure.directory-listing", "Directory listing is enabled", CATEGORY, "medium",
                               f"{path} shows an 'Index of' page", "Disable directory listing (autoindex off)."))
            break
    return out
