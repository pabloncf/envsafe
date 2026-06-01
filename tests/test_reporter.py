"""Tests for the reporter module."""

import json

import pytest

from envsafe.models import Finding, ScanResult, Severity
from envsafe.reporter import print_json_report, print_text_report


@pytest.fixture
def critical_result():
    return ScanResult(
        findings=[
            Finding(
                severity=Severity.CRITICAL,
                file_path=".env",
                rule_id="SECRET_AWS",
                message="AWS key found",
            )
        ],
        scanned_files=1,
        scan_duration=0.01,
    )


@pytest.fixture
def empty_result():
    return ScanResult(findings=[], scanned_files=0, scan_duration=0.001)


def test_text_report_no_findings(empty_result, capsys):
    print_text_report(empty_result)
    captured = capsys.readouterr()
    assert "No issues found" in captured.out


def test_text_report_with_findings(critical_result, capsys):
    print_text_report(critical_result)
    captured = capsys.readouterr()
    assert "SECRET_AWS" in captured.out
    assert ".env" in captured.out


def test_json_report_structure(critical_result, capsys):
    print_json_report(critical_result)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "findings" in data
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert data["findings"][0]["rule_id"] == "SECRET_AWS"
    assert "scanned_files" in data
    assert "scan_duration" in data


def test_json_report_empty(empty_result, capsys):
    print_json_report(empty_result)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["findings"] == []


def test_text_report_shows_severity_counts(capsys):
    result = ScanResult(
        findings=[
            Finding(severity=Severity.CRITICAL, file_path="a", rule_id="R1", message="m"),
            Finding(severity=Severity.WARNING, file_path="b", rule_id="R2", message="m"),
            Finding(severity=Severity.INFO, file_path="c", rule_id="R3", message="m"),
        ]
    )
    print_text_report(result)
    captured = capsys.readouterr()
    assert "1 critical" in captured.out
    assert "1 warnings" in captured.out
    assert "1 info" in captured.out


def test_text_report_finding_with_line_number(capsys):
    result = ScanResult(
        findings=[
            Finding(
                severity=Severity.WARNING,
                file_path="x.py",
                rule_id="R1",
                message="m",
                line_number=10,
            )
        ]
    )
    print_text_report(result)
    captured = capsys.readouterr()
    # reporter groups by file and shows line number in a dedicated column
    assert "x.py" in captured.out
    assert "10" in captured.out
