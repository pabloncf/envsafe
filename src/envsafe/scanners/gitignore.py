"""Gitignore validation scanner — ensures sensitive files are properly ignored."""

import fnmatch
from pathlib import Path

from envsafe.models import Finding, Severity
from envsafe.scanners.base import BaseScanner

_ENV_PATTERNS = [
    ".env",
    ".env*",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
]
_KEY_PATTERNS = ["*.pem", "*.key"]


def _gitignore_covers(gitignore_lines: list[str], filename: str) -> bool:
    """Return True if any line in .gitignore matches the filename."""
    for line in gitignore_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if fnmatch.fnmatch(filename, line):
            return True
        # Also match if the pattern without leading slash equals filename
        if line.startswith("/") and fnmatch.fnmatch(filename, line[1:]):
            return True
    return False


class GitignoreScanner(BaseScanner):
    """Checks that .gitignore protects sensitive files from accidental commits."""

    def scan(self, path: Path) -> list[Finding]:
        """Scan the project root for gitignore coverage of sensitive files.

        Args:
            path: Root directory to scan.

        Returns:
            List of findings for gitignore issues.
        """
        findings: list[Finding] = []
        gitignore_path = path / ".gitignore"
        has_env = (path / ".env").exists()

        if not has_env:
            return findings

        if not gitignore_path.exists():
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    file_path=".gitignore",
                    rule_id="GITIGNORE_MISSING",
                    message=".gitignore not found but .env exists — secrets may be committed",
                )
            )
            return findings

        lines = gitignore_path.read_text().splitlines()

        if not _gitignore_covers(lines, ".env"):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    file_path=".gitignore",
                    rule_id="GITIGNORE_ENV_EXPOSED",
                    message=".env is not listed in .gitignore — it may be accidentally committed",
                )
            )

        keys_covered = any(
            _gitignore_covers(lines, pat.lstrip("*")) or _gitignore_covers(lines, pat)
            for pat in _KEY_PATTERNS
        )
        if not keys_covered:
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    file_path=".gitignore",
                    rule_id="GITIGNORE_KEYS_EXPOSED",
                    message="Private key files (*.pem, *.key) are not covered by .gitignore",
                )
            )

        return findings
