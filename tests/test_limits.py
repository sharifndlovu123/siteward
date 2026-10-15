from siteward.web.limits import SlidingWindow, Slots


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_allows_up_to_limit_then_blocks():
    w = SlidingWindow(2, 3600, b"k", clock=Clock())
    assert [w.allow("1.2.3.4") for _ in range(3)] == [True, True, False]


def test_keys_are_independent():
    w = SlidingWindow(1, 3600, b"k", clock=Clock())
    assert w.allow("a") and w.allow("b") and not w.allow("a")


def test_window_slides():
    clock = Clock()
    w = SlidingWindow(1, 100, b"k", clock=clock)
    assert w.allow("a") and not w.allow("a")
    clock.now += 101
    assert w.allow("a")


def test_raw_keys_are_not_stored_in_memory():
    w = SlidingWindow(5, 100, b"k", clock=Clock())
    w.allow("203.0.113.9")
    assert all("203.0.113.9" not in key for key in w._hits)


def test_slots_bound_running_plus_queue():
    slots = Slots(concurrent=1, queue=1)
    assert slots.reserve() and slots.reserve() and not slots.reserve()
    slots.release()
    assert slots.reserve()
