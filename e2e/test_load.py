"""A light load test against the real server: it must degrade with 429/503, never time out or 500."""
import re
import statistics
import threading
import time

import httpx
import pytest


def hammer(n, fn):
    results, barrier = [None] * n, threading.Barrier(n)

    def worker(i):
        barrier.wait()
        try:
            results[i] = fn(i)
        except Exception as exc:  # a timeout or connection error is a failure of the server
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return results


def test_many_visitors_can_load_the_form_quickly(live_site):
    def visit(i):
        start = time.perf_counter()
        r = httpx.get(live_site + "/", timeout=10)
        return r.status_code, time.perf_counter() - start

    results = hammer(60, visit)
    assert all(isinstance(r, tuple) and r[0] == 200 for r in results), [r for r in results if not isinstance(r, tuple) or r[0] != 200]
    latencies = sorted(r[1] for r in results)
    assert latencies[int(len(latencies) * 0.95)] < 2.0, f"p95 {latencies[int(len(latencies) * 0.95)]:.2f}s, median {statistics.median(latencies):.2f}s"


def test_scan_flood_is_bounded_and_the_server_stays_up(live_site, target):
    def submit(i):
        with httpx.Client(base_url=live_site, timeout=15) as c:
            token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', c.get("/").text).group(1)
            r = c.post("/", data={"url": target.url, "authorised": "on", "csrfmiddlewaretoken": token})
            return r.status_code

    codes = hammer(40, submit)
    bad = [c for c in codes if c not in (302, 429, 503)]
    assert not bad, bad
    assert codes.count(302) <= 7  # MAX_CONCURRENT_SCANS (2) + MAX_QUEUE (5): the cap holds
    assert codes.count(302) >= 1
    assert httpx.get(live_site + "/", timeout=10).status_code == 200  # still serving afterwards
