"""Build the real image and check what it serves. Catches collectstatic / WhiteNoise / non-root problems."""
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")


@pytest.fixture(scope="module")
def container():
    tag = "siteward-e2e"
    subprocess.run(["docker", "build", "-q", "-t", tag, str(ROOT)], check=True, capture_output=True)
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", "127.0.0.1::8000", "-e", "SECRET_KEY=e2e",
         "-e", "ALLOWED_HOSTS=localhost,127.0.0.1", tag],
        check=True, capture_output=True, text=True).stdout.strip()
    port = subprocess.run(["docker", "port", cid, "8000/tcp"], check=True, capture_output=True,
                          text=True).stdout.split(":")[-1].strip()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/", timeout=1)
            break
        except OSError:
            time.sleep(0.2)
    else:
        logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True).stderr
        subprocess.run(["docker", "kill", cid], capture_output=True)
        raise RuntimeError(logs)
    yield base
    subprocess.run(["docker", "kill", cid], capture_output=True)


@pytest.mark.parametrize("path", ["/static/vendor/bootstrap.min.css", "/static/js/poll.js",
                                  "/static/img/logo-mark.svg", "/static/img/favicon.svg"])
def test_image_serves_static_files(container, path):
    assert urllib.request.urlopen(container + path, timeout=5).status == 200


def test_image_serves_security_headers(container):
    headers = urllib.request.urlopen(container + "/", timeout=5).headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["Referrer-Policy"] == "same-origin"
