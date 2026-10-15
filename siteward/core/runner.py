from __future__ import annotations

import importlib
import pkgutil
import queue
import threading
import time
from datetime import datetime, timezone

from siteward import __version__

from .context import build_context
from .models import CheckResult, ScanReport, Skip
from .netguard import FetchError

MAX_WORKERS = 8


class ScanError(Exception):
    """The scan could not start (target unreachable)."""


def discover_checks() -> list:
    import siteward.checks as package

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

    # Daemon threads (not a ThreadPoolExecutor): an abandoned, hung check must not keep the process alive.
    # At most MAX_WORKERS threads exist per scan; they pull checks from a queue and stop pulling once the
    # scan deadline has passed, so abandoned scans cannot accumulate threads or start new work.
    done: queue.Queue = queue.Queue()
    todo: queue.Queue = queue.Queue()
    stop = threading.Event()
    for module in modules:
        todo.put(module)

    def worker():
        while not stop.is_set():
            try:
                module = todo.get_nowait()
            except queue.Empty:
                return
            done.put((module, _run_one(module, ctx)))

    pending = {id(m): m for m in modules}
    for n in range(min(MAX_WORKERS, len(modules))):
        threading.Thread(target=worker, name=f"siteward-check-worker-{n}", daemon=True).start()
    deadline = time.monotonic() + timeout
    while pending:
        try:
            module, result = done.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            break
        pending.pop(id(module), None)
        emit(result)
    stop.set()
    for module in pending.values():
        emit(CheckResult(module.ID, module.CATEGORY, "error", message=f"timed out after {timeout:g}s"))

    if not pending:  # never close the client under a still-running abandoned check
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
