from webscan.core.models import CheckResult
from webscan.web.store import Store


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_create_and_get():
    store = Store(clock=Clock())
    entry = store.create("http://example.com/", {"ports": False})
    assert store.get(entry.id) is entry and entry.status == "queued"
    assert len(entry.id) >= 20  # unguessable


def test_unknown_id_returns_none():
    assert Store().get("nope") is None


def test_finished_entries_expire_after_ttl():
    clock = Clock()
    store = Store(ttl=900, clock=clock)
    entry = store.create("http://example.com/", {})
    entry.status, entry.finished = "done", clock.now
    clock.now += 899
    assert store.get(entry.id) is entry
    clock.now += 2
    assert store.get(entry.id) is None


def test_oldest_dropped_when_full():
    clock = Clock()
    store = Store(max_entries=2, clock=clock)
    first = store.create("http://a/", {})
    first.finished = clock.now
    clock.now += 1
    second = store.create("http://b/", {})
    second.finished = clock.now
    clock.now += 1
    third = store.create("http://c/", {})
    assert store.get(first.id) is None and store.get(second.id) and store.get(third.id)


def test_stuck_running_entries_are_eventually_dropped():
    clock = Clock()
    store = Store(clock=clock)
    entry = store.create("http://a/", {})
    clock.now += 3601
    assert store.get(entry.id) is None


def test_partial_report_reflects_results_so_far():
    entry = Store().create("http://example.com/", {"ports": False})
    entry.results.append(CheckResult("a", "T", "passed"))
    report = entry.partial_report()
    assert report.target == "http://example.com/" and len(report.results) == 1
