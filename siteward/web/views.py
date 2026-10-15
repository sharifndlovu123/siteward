from __future__ import annotations

import logging
import threading
import time
from urllib.parse import urlsplit

from django.conf import settings
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from siteward.core.models import SEVERITIES
from siteward.core.netguard import BlockedTarget, validate_target
from siteward.core.runner import ScanError, run_scan
from siteward.reports import FORMATS

from . import state, turnstile
from .store import StoreFull

logger = logging.getLogger(__name__)
BADGE = {"critical": "danger", "high": "danger", "medium": "warning", "low": "info", "info": "secondary"}


def client_ip(request) -> str:
    if settings.TRUST_CF_HEADERS:
        forwarded = request.META.get("HTTP_CF_CONNECTING_IP", "").strip()
        if forwarded:
            return forwarded
    return request.META.get("REMOTE_ADDR", "")


def _host_of(url: str) -> str:
    try:
        return urlsplit(url if "://" in url else "https://" + url).hostname or ""
    except ValueError:
        return ""


def _run(st, entry):
    """Background thread body: waits for a slot, runs the scan, records the outcome in memory."""
    try:
        with st.slots.sem:
            entry.status = "running"
            entry.report = run_scan(entry.url, entry.options, on_result=entry.results.append)
            entry.status = "done"
    except BlockedTarget as exc:
        entry.error, entry.status = f"Refused: {exc}", "error"
    except ScanError as exc:
        entry.error, entry.status = str(exc), "error"
    except Exception as exc:  # never log details: they can contain the target
        logger.error("scan failed: %s", type(exc).__name__)
        entry.error, entry.status = "Unexpected error while scanning.", "error"
    finally:
        entry.finished = time.time()
        st.slots.release()


def _start_scan(request):
    """Returns (entry, error_message, http_status)."""
    st, ip = state.get(), client_ip(request)
    url = request.POST.get("url", "").strip()
    host = _host_of(url)

    if not request.POST.get("authorised"):
        return None, "Please confirm you are authorised to test this target.", 400
    if settings.PUBLIC_MODE and not turnstile.verify(request.POST.get("cf-turnstile-response", ""), ip, settings.TURNSTILE_SECRET):
        st.abuse.record(ip, host, {}, "captcha_failed")
        return None, "Verification failed. Please try again.", 400
    if not st.ip_limiter.allow(ip):
        st.abuse.record(ip, host, {}, "rate_limited")
        return None, "Rate limit reached. Please try again later.", 429

    allow_private = settings.ALLOW_PRIVATE_TARGETS and not settings.PUBLIC_MODE
    try:
        target = validate_target(url, allow_private)
    except BlockedTarget as exc:
        st.abuse.record(ip, host, {}, "blocked")
        return None, f"Cannot scan that target: {exc}", 400
    if not st.target_limiter.allow(target.host):
        st.abuse.record(ip, target.host, {}, "rate_limited")
        return None, "This site has been scanned too often recently. Please try again later.", 429
    if not st.slots.reserve():
        st.abuse.record(ip, target.host, {}, "busy")
        return None, "The scanner is busy. Please try again shortly.", 503

    ports = bool(request.POST.get("ports")) and not settings.PUBLIC_MODE
    options = {"ports": ports, "allow_private": allow_private, "min_interval": settings.SCAN_MIN_INTERVAL}
    try:
        entry = st.store.create(target.url, options)
        threading.Thread(target=_run, args=(st, entry), daemon=True).start()
    except (StoreFull, RuntimeError):
        st.slots.release()  # do not leak the reserved slot
        st.abuse.record(ip, target.host, {}, "busy")
        return None, "The scanner is busy. Please try again shortly.", 503
    st.abuse.record(ip, target.host, {"ports": ports}, "accepted")
    return entry, "", 302


@require_http_methods(["GET", "POST"])
@never_cache
def index(request):
    context = {"turnstile_site_key": settings.TURNSTILE_SITE_KEY if settings.PUBLIC_MODE else "", "error": "", "url": ""}
    if request.method == "POST":
        entry, error, status = _start_scan(request)
        if entry:
            return redirect("scan_detail", scan_id=entry.id)
        context.update(error=error, url=request.POST.get("url", ""))
        return render(request, "index.html", context, status=status)
    return render(request, "index.html", context)


def _page(entry):
    st = state.get()
    report = entry.report or entry.partial_report()
    counts = [(s, report.counts[s], BADGE[s]) for s in reversed(SEVERITIES)]
    return {
        "entry": entry,
        "report": report,
        "findings": [{"f": f, "badge": BADGE[f.severity]} for f in report.findings],
        "passed": [r for r in report.results if r.status == "passed"],
        "skipped": [r for r in report.results if r.status == "skipped"],
        "errors": [r for r in report.results if r.status == "error"],
        "counts": counts,
        "done": entry.status in ("done", "error"),
        "completed": len(report.results),
        "total": st.total_checks,
    }


def _expired(request, status_only=False):
    response = render(request, "_results.html" if status_only else "scan.html",
                      {"expired": True}, status=404)
    response["X-Scan-Done"] = "1"
    return response


@require_GET
@never_cache
def scan_detail(request, scan_id):
    entry = state.get().store.get(scan_id)
    if entry is None:
        return _expired(request)
    return render(request, "scan.html", {**_page(entry), "scan_id": scan_id,
                                         "ttl_minutes": settings.SCAN_TTL_SECONDS // 60})


@require_GET
@never_cache
def scan_status(request, scan_id):
    entry = state.get().store.get(scan_id)
    if entry is None:
        return _expired(request, status_only=True)
    page = _page(entry)
    response = render(request, "_results.html", {**page, "scan_id": scan_id})
    response["X-Scan-Done"] = "1" if page["done"] else "0"
    return response


@require_GET
@never_cache
def scan_export(request, scan_id):
    entry = state.get().store.get(scan_id)
    if entry is None:
        raise Http404("scan expired")
    fmt = request.GET.get("format", "")
    if fmt not in FORMATS:
        return HttpResponse("format must be json, md or html", status=400)
    if entry.report is None:
        return HttpResponse("scan has not finished", status=409)
    render_fn, content_type, extension = FORMATS[fmt]
    response = HttpResponse(render_fn(entry.report), content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="siteward-report.{extension}"'
    return response


@require_GET
def policy(request):
    return render(request, "policy.html", {"contact_email": settings.CONTACT_EMAIL,
                                           "retention_days": settings.ABUSE_LOG_RETENTION_DAYS,
                                           "ttl_minutes": settings.SCAN_TTL_SECONDS // 60})


def csrf_failure(request, reason=""):
    """Friendly 403 for failed CSRF checks: state the reason and how to recover. Never logs request data."""
    logger.warning("csrf rejected: %s", reason)
    return render(request, "csrf_failed.html", {"reason": reason}, status=403)
