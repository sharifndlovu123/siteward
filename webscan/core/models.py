"""Plain data types shared by every layer. No framework imports."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime

# C0/C1 control characters except tab and newline: target-controlled text must never be able to
# carry terminal escape sequences into a report.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(text: str) -> str:
    return _CONTROL.sub("�", text)


SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {name: i for i, name in enumerate(SEVERITIES)}
_GRADE = {"info": "A", "low": "B", "medium": "C", "high": "D", "critical": "F"}


def severity_rank(severity: str) -> int:
    return _RANK[severity]


class Skip(Exception):
    """Raised by a check that does not apply to this target."""


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    evidence: str = ""
    remediation: str = ""

    def __post_init__(self):
        if self.severity not in _RANK:
            raise ValueError(f"unknown severity: {self.severity!r}")
        self.title, self.evidence, self.remediation = clean(self.title), clean(self.evidence), clean(self.remediation)


@dataclass
class CheckResult:
    check_id: str
    category: str
    status: str  # passed | findings | skipped | error
    findings: list[Finding] = field(default_factory=list)
    message: str = ""

    def __post_init__(self):
        self.message = clean(self.message)


@dataclass
class ScanReport:
    target: str
    started: datetime
    finished: datetime
    version: str
    options: dict
    results: list[CheckResult]

    @property
    def findings(self) -> list[Finding]:
        found = [f for r in self.results for f in r.findings]
        return sorted(found, key=lambda f: -_RANK[f.severity])

    @property
    def counts(self) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def grade(self) -> str:
        found = self.findings
        return _GRADE[found[0].severity] if found else "A"

    @property
    def incomplete(self) -> bool:
        return any(r.status == "error" for r in self.results)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started": self.started.isoformat(),
            "finished": self.finished.isoformat(),
            "version": self.version,
            "options": self.options,
            "grade": self.grade,
            "incomplete": self.incomplete,
            "counts": self.counts,
            "results": [
                {
                    "check_id": r.check_id,
                    "category": r.category,
                    "status": r.status,
                    "message": r.message,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in self.results
            ],
        }
