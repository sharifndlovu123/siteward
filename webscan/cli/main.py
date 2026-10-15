from __future__ import annotations

from pathlib import Path

import typer

from webscan.core.models import SEVERITIES, severity_rank
from webscan.core.netguard import BlockedTarget
from webscan.core.runner import ScanError, run_scan
from webscan.reports import FORMATS, render

app = typer.Typer(add_completion=False, help="Passive web security scanner.")
NOTICE = "Only scan sites you own or are authorised to test."


@app.callback()
def main():
    """webscan: run passive security checks against a URL."""


def _err(message: str):
    typer.echo(message, err=True)


@app.command()
def scan(
    url: str = typer.Argument(..., help="Site to scan, e.g. https://example.com"),
    ports: bool = typer.Option(False, "--ports", help="Also run the opt-in TCP port check."),
    fmt: str = typer.Option("md", "--format", help="Report format: json, md or html."),
    out: Path | None = typer.Option(None, "--out", help="Write the report to this file instead of stdout."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if a finding is at/above: info|low|medium|high|critical|never."),
    allow_private: bool = typer.Option(False, "--allow-private", help="Allow private/loopback targets (local development only)."),
):
    if fmt not in FORMATS:
        _err(f"Error: --format must be one of {', '.join(FORMATS)}")
        raise typer.Exit(2)
    if fail_on != "never" and fail_on not in SEVERITIES:
        _err(f"Error: --fail-on must be one of {', '.join(SEVERITIES)}, never")
        raise typer.Exit(2)

    _err(NOTICE)
    try:
        report = run_scan(
            url,
            {"ports": ports, "allow_private": allow_private},
            on_result=lambda r: _err(f"  [{r.status:8}] {r.check_id}"),
        )
    except BlockedTarget as exc:
        _err(f"Refused: {exc}")
        raise typer.Exit(2)
    except ScanError as exc:
        _err(f"Error: {exc}")
        raise typer.Exit(2)

    text = render(report, fmt)
    if out:
        out.write_text(text, encoding="utf-8")
        _err(f"Report written to {out}")
    else:
        typer.echo(text)

    if fail_on != "never" and any(severity_rank(f.severity) >= severity_rank(fail_on) for f in report.findings):
        raise typer.Exit(1)
