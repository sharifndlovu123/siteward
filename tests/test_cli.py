import json

from typer.testing import CliRunner

from webscan.cli.main import app

runner = CliRunner()


def scan(server, *args):
    return runner.invoke(app, ["scan", server.url, "--allow-private", *args])


def test_markdown_report_to_stdout_and_exit_zero_for_medium_findings(server):
    result = scan(server)
    assert result.exit_code == 0  # plain fake server: medium findings only, default --fail-on high
    assert "# Security scan" in result.stdout


def test_fail_on_medium_exits_one(server):
    assert scan(server, "--fail-on", "medium").exit_code == 1


def test_high_severity_finding_fails_by_default(server):
    server.add("/.env", "SECRET_KEY=abc\n")
    assert scan(server).exit_code == 1


def test_fail_on_never_always_exits_zero(server):
    server.add("/.env", "SECRET_KEY=abc\n")
    assert scan(server, "--fail-on", "never").exit_code == 0


def test_json_output_is_valid(server):
    result = scan(server, "--format", "json")
    assert json.loads(result.stdout)["target"].startswith("http://127.0.0.1")


def test_out_file_is_written(server, tmp_path):
    out = tmp_path / "report.html"
    result = scan(server, "--format", "html", "--out", str(out))
    assert result.exit_code == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_private_target_refused_without_flag(server):
    result = runner.invoke(app, ["scan", server.url])
    assert result.exit_code == 2 and "Refused" in result.output


def test_unreachable_target_exits_two():
    result = runner.invoke(app, ["scan", "http://127.0.0.1:1", "--allow-private"])
    assert result.exit_code == 2 and "Error" in result.output


def test_bad_format_and_bad_fail_on_exit_two(server):
    assert scan(server, "--format", "pdf").exit_code == 2
    assert scan(server, "--fail-on", "scary").exit_code == 2


def test_port_check_flag_enables_the_check(server):
    result = scan(server, "--ports", "--format", "json")
    data = json.loads(result.stdout)
    ports = next(r for r in data["results"] if r["check_id"] == "ports.common")
    assert ports["status"] != "skipped" and data["options"]["ports"] is True
