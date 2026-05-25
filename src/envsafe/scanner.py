"""Orchestrates all scanners and aggregates results."""

import fnmatch
import time
from pathlib import Path

from envsafe.models import Finding, ScanResult, Severity
from envsafe.scanners.base import BaseScanner


def _default_scanners() -> list[BaseScanner]:
    """Return the default list of enabled scanners."""
    from envsafe.scanners.docker import DockerScanner
    from envsafe.scanners.env_example import EnvExampleScanner
    from envsafe.scanners.gitignore import GitignoreScanner
    from envsafe.scanners.secrets import SecretScanner
    from envsafe.scanners.weak_credentials import WeakCredentialScanner

    return [
        SecretScanner(),
        GitignoreScanner(),
        DockerScanner(),
        WeakCredentialScanner(),
        EnvExampleScanner(),
    ]


class Scanner:
    """Runs all registered scanners and returns a combined ScanResult."""

    def __init__(self, scanners: list[BaseScanner] | None = None) -> None:
        """Initialize with an optional list of scanners.

        Args:
            scanners: Scanners to use. Defaults to the full built-in set.
        """
        self._scanners: list[BaseScanner] = (
            scanners if scanners is not None else _default_scanners()
        )

    def run(self, path: Path, config=None) -> ScanResult:
        """Run all scanners against the given path, applying config filters.

        Args:
            path: Root directory to scan.
            config: Optional EnvSafeConfig. When provided, disabled rules and
                    severity overrides are applied to findings.

        Returns:
            Aggregated ScanResult with all findings.
        """
        start = time.monotonic()
        all_findings: list[Finding] = []

        for scanner in self._scanners:
            all_findings.extend(scanner.scan(path))

        if config:
            all_findings = self._apply_config(all_findings, config)

        duration = time.monotonic() - start
        return ScanResult(
            findings=all_findings,
            scanned_files=0,
            scan_duration=duration,
        )

    @staticmethod
    def _apply_config(findings: list[Finding], config) -> list[Finding]:
        """Filter and override findings according to config rules."""
        result: list[Finding] = []
        for f in findings:
            if f.rule_id in config.rules.disable:
                continue
            if any(fnmatch.fnmatch(f.file_path, pat) for pat in config.exclude):
                continue
            if f.rule_id in config.rules.severity_override:
                override = config.rules.severity_override[f.rule_id]
                f = Finding(
                    severity=Severity(override.upper()),
                    file_path=f.file_path,
                    rule_id=f.rule_id,
                    message=f.message,
                    line_number=f.line_number,
                )
            result.append(f)
        return result
