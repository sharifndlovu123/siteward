"""Plain data types shared by every layer. No framework imports."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

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


@dataclass
class CheckResult:
    check_id: str
    category: str
    status: str  # passed | findings | skipped | error
    findings: list[Finding] = field(default_factory=list)
    message: str = ""


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
