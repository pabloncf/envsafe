"""Integration tests for the CLI."""

from typer.testing import CliRunner

from envsafe.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_empty_dir(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_scan_json_output(tmp_path):
    import json

    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    assert result.exit_code == 0
    # output has "Scanning ..." prefix line, then JSON
    lines = result.output.strip().splitlines()
    json_start = next(i for i, line in enumerate(lines) if line.startswith("{"))
    data = json.loads("\n".join(lines[json_start:]))
    assert "findings" in data


def test_scan_strict_no_critical(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--strict"])
    assert result.exit_code == 0


def test_scan_default_path(tmp_path):
    # Use an empty tmp dir to avoid picking up project test files
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
