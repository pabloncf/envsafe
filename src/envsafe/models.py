"""Data models for envsafe scan results."""

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security issue found during scanning."""

    severity: Severity
    file_path: str
    rule_id: str
    message: str
    line_number: int | None = None


@dataclass
class ScanResult:
    """Aggregated result of a full scan."""

    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scan_duration: float = 0.0
