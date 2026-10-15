from .html_report import to_html
from .json_report import to_json
from .markdown_report import to_markdown

FORMATS = {
    "json": (to_json, "application/json", "json"),
    "md": (to_markdown, "text/markdown; charset=utf-8", "md"),
    "html": (to_html, "text/html; charset=utf-8", "html"),
}


def render(report, fmt: str) -> str:
    return FORMATS[fmt][0](report)
