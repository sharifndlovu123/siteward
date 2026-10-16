"""Browser tests against the real app: gunicorn + collectstatic + WhiteNoise, like the Docker image.

Run with:  pip install -e '.[e2e]' && playwright install chromium && pytest e2e
The Django test client cannot see CSP violations, missing static files or JS errors; a real browser can.
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from tests.fake_server import FakeServer

ROOT = Path(__file__).resolve().parent.parent


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def start_site(tmp_path_factory):
    """Factory: start the real app (gunicorn + collectstatic) with extra env vars; returns its base URL."""
    procs = []

    def start(**extra_env):
        static_root = tmp_path_factory.mktemp("staticfiles")
        port = _free_port()
        env = {
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "siteward.web.settings",
            "STATIC_ROOT": str(static_root),
            "SECRET_KEY": "e2e-only",
            "ALLOWED_HOSTS": "127.0.0.1,localhost",
            "ALLOW_PRIVATE_TARGETS": "1",
            "SCAN_MIN_INTERVAL": "0",
            "RATE_PER_IP": "1000",
            "RATE_PER_TARGET": "1000",
            **extra_env,
        }
        subprocess.run([sys.executable, "-m", "django", "collectstatic", "--noinput"],
                       env=env, cwd=ROOT, check=True, capture_output=True)
        proc = subprocess.Popen(
            [sys.executable, "-m", "gunicorn", "siteward.web.wsgi:application",
             "--bind", f"127.0.0.1:{port}", "--workers", "1", "--threads", "8"],
            env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs.append(proc)
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/", timeout=1)
                return base
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError(proc.stderr.read().decode())
                time.sleep(0.1)
        raise RuntimeError("gunicorn did not start")

    yield start
    for proc in procs:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="session")
def live_site(start_site):
    return start_site()


@pytest.fixture
def target():
    """A local site for the scanner to scan. Missing most security headers on purpose."""
    s = FakeServer()
    s.add("/", "<html><body>ok</body></html>", headers=[("Content-Type", "text/html")])
    s.start()
    yield s
    s.stop()


@pytest.fixture
def page(page, request):
    """Playwright page that fails the test on any console error, JS error or failed request.

    Mark a test with @pytest.mark.expects_http_error when it deliberately provokes a 4xx page.
    """
    problems = []
    page.on("console", lambda m: problems.append(f"console: {m.text}") if m.type == "error" else None)
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    # Chromium reports attachment downloads as failed navigations, so exports are exempt.
    page.on("requestfailed", lambda r: problems.append(f"requestfailed: {r.url}") if "/export/" not in r.url else None)
    page.on("response", lambda r: problems.append(f"{r.status}: {r.url}") if r.status >= 400 and "/scan/" not in r.url else None)
    yield page
    if request.node.get_closest_marker("expects_http_error"):
        problems = [p for p in problems if not p.startswith(("4", "console: Failed to load resource"))]
    assert not problems, "\n".join(problems)
