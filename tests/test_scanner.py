"""Tests for the Scanner orchestrator."""

from pathlib import Path

from envsafe.models import Finding, Severity
from envsafe.scanner import Scanner
from envsafe.scanners.base import BaseScanner


class _FakeScanner(BaseScanner):
    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    def scan(self, path: Path) -> list[Finding]:
        return self._findings


def test_scanner_no_findings(tmp_project):
    scanner = Scanner(scanners=[_FakeScanner([])])
    result = scanner.run(tmp_project)
    assert result.findings == []
    assert result.scan_duration >= 0


def test_scanner_aggregates_findings(tmp_project):
    f1 = Finding(severity=Severity.CRITICAL, file_path="a.env", rule_id="R1", message="msg1")
    f2 = Finding(severity=Severity.WARNING, file_path="b.env", rule_id="R2", message="msg2")
    scanner = Scanner(scanners=[_FakeScanner([f1]), _FakeScanner([f2])])
    result = scanner.run(tmp_project)
    assert len(result.findings) == 2
    assert result.findings[0].rule_id == "R1"
    assert result.findings[1].rule_id == "R2"


def test_scanner_default_scanners(tmp_project):
    scanner = Scanner()
    result = scanner.run(tmp_project)
    assert isinstance(result.findings, list)
