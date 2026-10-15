import re

from siteward.core.models import SEVERITIES

_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~])")


def _esc(text) -> str:
    """Escape target-controlled text used outside code fences."""
    return _SPECIAL.sub(r"\\\1", str(text).replace("\r", " ").replace("\n", " "))


def _fence(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    mark = "`" * max(3, longest + 1)
    return f"{mark}\n{text}\n{mark}"


def to_markdown(report) -> str:
    d = report.to_dict()
    lines = [
        f"# Security scan: {_esc(d['target'])}",
        "",
        f"- **Grade:** {d['grade']}" + (" (incomplete: some checks errored)" if d["incomplete"] else ""),
        f"- **Scanned:** {d['started']}",
        f"- **Tool:** siteward {d['version']} (port check: {'on' if d['options'].get('ports') else 'off'})",
        "- **Counts:** " + ", ".join(f"{s} {d['counts'][s]}" for s in reversed(SEVERITIES)),
        "",
        "## Findings",
        "",
    ]
    findings = report.findings
    if not findings:
        lines += ["No findings.", ""]
    for f in findings:
        lines += [f"### [{f.severity.upper()}] {_esc(f.title)}", ""]
        if f.evidence:
            lines += ["Evidence:", "", _fence(f.evidence), ""]
        if f.remediation:
            lines += [f"**Fix:** {_esc(f.remediation)}", ""]

    for heading, status in (("Errored checks", "error"), ("Skipped checks", "skipped"), ("Passed checks", "passed")):
        rows = [r for r in d["results"] if r["status"] == status]
        if rows:
            lines += [f"## {heading}", ""]
            for r in rows:
                extra = f": {_esc(r['message'])}" if r["message"] else ""
                lines.append(f"- `{r['check_id']}`{extra}")
            lines.append("")
    return "\n".join(lines)
