"""Weak credential scanner — detects common/short passwords in config files."""

import re
from pathlib import Path

from envsafe.models import Finding, Severity
from envsafe.scanners.base import BaseScanner

_SENSITIVE_VAR = re.compile(
    r"^[ \t]*(?:export\s+)?"
    r"(?P<var>[A-Z_]*(?:PASSWORD|PASSWD|SECRET|KEY|TOKEN)[A-Z_]*)\s*=\s*(?P<val>.+)",
    re.IGNORECASE | re.MULTILINE,
)

_COMMON_WEAK = {
    "password",
    "123456",
    "12345678",
    "admin",
    "root",
    "changeme",
    "test",
    "default",
    "secret",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "pass",
}

_SCANNED_EXTENSIONS = {".env", ".cfg", ".ini", ".properties"}


def _is_scannable(file: Path) -> bool:
    return file.name.startswith(".env") or file.suffix in _SCANNED_EXTENSIONS


def _iter_files(path: Path):
    for item in path.rglob("*"):
        if item.is_file() and _is_scannable(item):
            yield item


class WeakCredentialScanner(BaseScanner):
    """Detects common or too-short passwords in environment and config files."""

    def scan(self, path: Path) -> list[Finding]:
        """Scan for weak credential values in config files.

        Args:
            path: Root directory to scan.

        Returns:
            List of findings for weak credentials.
        """
        findings: list[Finding] = []
        for file in _iter_files(path):
            findings.extend(self._scan_file(file, path))
        return findings

    def _scan_file(self, file: Path, root: Path) -> list[Finding]:
        try:
            text = file.read_text(errors="replace")
        except OSError:
            return []

        rel = str(file.relative_to(root))
        results: list[Finding] = []

        for match in _SENSITIVE_VAR.finditer(text):
            var = match.group("var")
            val = match.group("val").strip().strip('"').strip("'")

            if not val or val.startswith("$"):
                continue

            if val.lower() in _COMMON_WEAK:
                line_number = text[: match.start()].count("\n") + 1
                results.append(
                    Finding(
                        severity=Severity.WARNING,
                        file_path=rel,
                        line_number=line_number,
                        rule_id="WEAK_PASSWORD_COMMON",
                        message=f"Common weak password detected in variable {var!r}",
                    )
                )
            elif len(val) < 8 and any(kw in var.upper() for kw in ("PASSWORD", "PASSWD", "SECRET")):
                line_number = text[: match.start()].count("\n") + 1
                results.append(
                    Finding(
                        severity=Severity.WARNING,
                        file_path=rel,
                        line_number=line_number,
                        rule_id="WEAK_PASSWORD_SHORT",
                        message=f"Password in {var!r} is too short (< 8 characters)",
                    )
                )

        return results
