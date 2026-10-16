"""The post-deploy smoke script must pass against a healthy instance and fail against a broken one."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("smoke_deployed", Path(__file__).parent.parent / "scripts" / "smoke_deployed.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_smoke_passes_on_a_healthy_local_instance(live_site, capsys):
    code = smoke.main([live_site, "--allow-http", "--accept", "transport.no-https-redirect"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "static file /static/img/logo-mark.svg" in out


def test_smoke_fails_when_the_site_is_down(capsys):
    assert smoke.main(["http://127.0.0.1:9", "--allow-http"]) == 1
    assert "FAIL  site is reachable" in capsys.readouterr().out


def test_smoke_flags_a_site_missing_the_security_headers(start_site, target, capsys):
    """Point the script at the plain fake target: no form, no headers, no static files."""
    code = smoke.main([target.url, "--allow-http", "--no-scan"])
    out = capsys.readouterr().out
    assert code == 1 and "FAIL  header content-security-policy" in out and "FAIL  scan form is present" in out
