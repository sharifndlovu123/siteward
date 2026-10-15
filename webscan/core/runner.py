from __future__ import annotations

import importlib
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import datetime, timezone

from webscan import __version__

from .context import build_context
from .models import CheckResult, ScanReport, Skip
from .netguard import FetchError

MAX_WORKERS = 8


class ScanError(Exception):
    """The scan could not start (target unreachable)."""


def discover_checks() -> list:
    import webscan.checks as package

    modules = []
    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{info.name}")
        if hasattr(module, "ID") and hasattr(module, "run"):
            modules.append(module)
    return sorted(modules, key=lambda m: m.ID)


def _run_one(module, ctx) -> CheckResult:
    opt_in = getattr(module, "OPT_IN", None)
    if opt_in and not ctx.options.get(opt_in):
        return CheckResult(module.ID, module.CATEGORY, "skipped", message=f"opt-in check; not enabled ({opt_in})")
    try:
        findings = list(module.run(ctx))
    except Skip as skip:
        return CheckResult(module.ID, module.CATEGORY, "skipped", message=str(skip))
    except Exception as exc:  # a crashing check must never look like a pass
        return CheckResult(module.ID, module.CATEGORY, "error", message=f"{type(exc).__name__}: {exc}")
    return CheckResult(module.ID, module.CATEGORY, "findings" if findings else "passed", findings=findings)


def run_scan(url, options=None, on_result=None, checks=None, timeout=60.0, client=None) -> ScanReport:
    options = dict(options or {})
    started = datetime.now(timezone.utc)
    try:
        ctx = build_context(url, options, client=client)  # BlockedTarget propagates
    except FetchError as exc:
        raise ScanError(f"could not reach the target: {exc}") from exc

    modules = checks if checks is not None else discover_checks()
    results: list[CheckResult] = []

    def emit(result: CheckResult):
        results.append(result)
        if on_result:
            on_result(result)

    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures = {pool.submit(_run_one, module, ctx): module for module in modules}
    finished = set()
    try:
        for future in as_completed(futures, timeout=timeout):
            finished.add(future)
            emit(future.result())
    except FuturesTimeout:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    for future, module in futures.items():
        if future not in finished:
            emit(CheckResult(module.ID, module.CATEGORY, "error", message=f"timed out after {timeout:g}s"))

    ctx.client.close()
    results.sort(key=lambda r: r.check_id)
    return ScanReport(
        target=ctx.target.url,
        started=started,
        finished=datetime.now(timezone.utc),
        version=__version__,
        options={"ports": bool(options.get("ports"))},
        results=results,
    )
