"""Tests for envsafe data models."""

from envsafe.models import Finding, ScanResult, Severity


def test_severity_values():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.WARNING.value == "WARNING"
    assert Severity.INFO.value == "INFO"


def test_finding_defaults():
    finding = Finding(
        severity=Severity.CRITICAL,
        file_path=".env",
        rule_id="SECRET_AWS",
        message="AWS key found",
    )
    assert finding.line_number is None
    assert finding.severity == Severity.CRITICAL


def test_finding_with_line_number():
    finding = Finding(
        severity=Severity.WARNING,
        file_path="config.py",
        rule_id="SECRET_GENERIC",
        message="Generic key found",
        line_number=42,
    )
    assert finding.line_number == 42


def test_scan_result_defaults():
    result = ScanResult()
    assert result.findings == []
    assert result.scanned_files == 0
    assert result.scan_duration == 0.0


def test_scan_result_with_findings():
    findings = [
        Finding(
            severity=Severity.CRITICAL, file_path=".env", rule_id="SECRET_AWS", message="AWS key"
        ),
        Finding(
            severity=Severity.INFO,
            file_path=".gitignore",
            rule_id="GITIGNORE_MISSING",
            message="No gitignore",
        ),
    ]
    result = ScanResult(findings=findings, scanned_files=3, scan_duration=0.05)
    assert len(result.findings) == 2
    assert result.scanned_files == 3
