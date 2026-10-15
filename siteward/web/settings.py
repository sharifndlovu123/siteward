import os
import secrets
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent


def _bool(name, default=False):
    return os.environ.get(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


def _int(name, default):
    return int(os.environ.get(name, default))


DEBUG = _bool("DEBUG")
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(50)  # no sessions are used, so a per-start key is fine
ALLOWED_HOSTS = [h for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h]
CSRF_TRUSTED_ORIGINS = [o for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if o]

# --- siteward -----------------------------------------------------------------------------------
PUBLIC_MODE = _bool("PUBLIC_MODE")
TRUST_CF_HEADERS = _bool("TRUST_CF_HEADERS")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")
ABUSE_LOG = _bool("ABUSE_LOG", default=PUBLIC_MODE)
ABUSE_LOG_DIR = os.environ.get("ABUSE_LOG_DIR", "/var/log/siteward")
ABUSE_LOG_KEY = os.environ.get("ABUSE_LOG_KEY", "")
ABUSE_LOG_RETENTION_DAYS = _int("ABUSE_LOG_RETENTION_DAYS", 30)
RATE_PER_IP = _int("RATE_PER_IP", 5)
RATE_PER_TARGET = _int("RATE_PER_TARGET", 3)
RATE_WINDOW = _int("RATE_WINDOW", 3600)
MAX_CONCURRENT_SCANS = _int("MAX_CONCURRENT_SCANS", 2)
MAX_QUEUE = _int("MAX_QUEUE", 5)
SCAN_TTL_SECONDS = _int("SCAN_TTL_SECONDS", 900)
MAX_STORED_SCANS = _int("MAX_STORED_SCANS", 20)
SCAN_MIN_INTERVAL = float(os.environ.get("SCAN_MIN_INTERVAL", "0.05"))
ALLOW_PRIVATE_TARGETS = _bool("ALLOW_PRIVATE_TARGETS")
THEME = os.environ.get("THEME", "bootstrap")
DONATE_URL = os.environ.get("DONATE_URL", "")
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "")

if PUBLIC_MODE:  # fail fast on a misconfigured public deployment (tests flip settings.PUBLIC_MODE after import)
    missing = [n for n, v in (("TURNSTILE_SECRET", TURNSTILE_SECRET), ("TURNSTILE_SITE_KEY", TURNSTILE_SITE_KEY)) if not v]
    if ABUSE_LOG and not ABUSE_LOG_KEY:
        missing.append("ABUSE_LOG_KEY")
    if missing:
        raise ImproperlyConfigured(f"PUBLIC_MODE requires: {', '.join(missing)}")

# --- Django (deliberately minimal: no database, sessions, auth or admin) --------------------------
DATABASES = {}
INSTALLED_APPS = ["django.contrib.staticfiles"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "siteward.web.middleware.SecurityHeadersMiddleware",
]
ROOT_URLCONF = "siteward.web.urls"
WSGI_APPLICATION = "siteward.web.wsgi.application"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "OPTIONS": {"context_processors": ["django.template.context_processors.request", "siteward.web.context.theme"]},
}]
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = Path(os.environ.get("STATIC_ROOT", Path.cwd() / "staticfiles"))
USE_TZ = True
CSRF_COOKIE_NAME = "siteward_csrftoken"  # own name: other Django apps on localhost share "csrftoken" across ports
CSRF_COOKIE_SECURE = PUBLIC_MODE
CSRF_COOKIE_HTTPONLY = True
CSRF_FAILURE_VIEW = "siteward.web.views.csrf_failure"
X_FRAME_OPTIONS = "DENY"
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    # Security warnings (rejected CSRF, bad Host header) must be visible in production logs.
    "loggers": {
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "siteward": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}
