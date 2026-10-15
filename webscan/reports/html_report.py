from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from webscan.core.models import SEVERITIES

_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent)), autoescape=True)


def to_html(report) -> str:
    d = report.to_dict()
    template = _env.get_template("report.html.j2")
    return template.render(
        r=d,
        severities=list(reversed(SEVERITIES)),
        findings=report.findings,
        errors=[x for x in d["results"] if x["status"] == "error"],
        skipped=[x for x in d["results"] if x["status"] == "skipped"],
        passed=[x for x in d["results"] if x["status"] == "passed"],
    )
