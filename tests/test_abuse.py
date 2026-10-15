import json
from datetime import datetime, timezone

from siteward.web.abuse import AbuseLog, lookup


class Clock:
    def __init__(self, ts):
        self.ts = ts

    def __call__(self):
        return self.ts


T0 = datetime(2026, 10, 15, 14, 2, tzinfo=timezone.utc).timestamp()


def test_record_writes_hashed_target_and_no_findings(tmp_path):
    log = AbuseLog(tmp_path, "secret", clock=Clock(T0))
    log.record("203.0.113.9", "Example.com", {"ports": False}, "accepted")
    text = next(tmp_path.glob("abuse-*.log")).read_text()
    line = json.loads(text.strip())
    assert line["ip"] == "203.0.113.9" and line["outcome"] == "accepted" and line["options"] == {"ports": False}
    assert "example.com" not in text.lower()
    assert line["target_hmac"] == log.target_hmac("example.com")


def test_lookup_finds_ip_from_reported_hostname(tmp_path):
    log = AbuseLog(tmp_path, "secret", clock=Clock(T0))
    log.record("203.0.113.9", "victim.example", {}, "accepted")
    log.record("198.51.100.1", "other.example", {}, "accepted")
    hits = lookup(tmp_path, "secret", "VICTIM.example")
    assert [h["ip"] for h in hits] == ["203.0.113.9"]
    assert lookup(tmp_path, "wrong-key", "victim.example") == []


def test_old_files_are_pruned(tmp_path):
    old = tmp_path / "abuse-2026-01-01.log"
    old.write_text("{}\n")
    log = AbuseLog(tmp_path, "secret", retention_days=30, clock=Clock(T0))
    log.record("203.0.113.9", "a.example", {}, "accepted")
    assert not old.exists()


def test_disabled_log_writes_nothing(tmp_path):
    AbuseLog(tmp_path, "secret", enabled=False, clock=Clock(T0)).record("1.1.1.1", "a.example", {}, "accepted")
    assert list(tmp_path.iterdir()) == []


def test_unwritable_directory_does_not_raise(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    AbuseLog(blocked / "sub", "secret", clock=Clock(T0)).record("1.1.1.1", "a.example", {}, "accepted")
