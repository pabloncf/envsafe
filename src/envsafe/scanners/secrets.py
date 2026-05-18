"""Secret detection scanner — detects hardcoded credentials and API keys."""

import re
from pathlib import Path

from envsafe.models import Finding, Severity
from envsafe.scanners.base import BaseScanner

_SCANNED_EXTENSIONS = {
    ".env",
    ".yml",
    ".yaml",
    ".py",
    ".properties",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
}
# Only apply the generic KEY/SECRET/TOKEN variable check to env-like files,
# not to source code (.py, .toml, .json, .yml) where variable names like
# `_AWS_KEY = re.compile(...)` or `keywords = [...]` would cause false positives.
_GENERIC_KEY_EXTENSIONS = {".env", ".cfg", ".ini", ".properties"}
_IGNORED_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv"}

_PLACEHOLDERS = re.compile(
    r"^(changeme|xxx+|your[_-]?key[_-]?here|your[_-]?secret|dummy|example|placeholder|none|null|true|false|0|1|\$\{.+\}|<.+>|%\w+%)$",
    re.IGNORECASE,
)

_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_PRIVATE_KEY = re.compile(r"-----BEGIN\s+[\w ]*PRIVATE KEY-----")
_CONN_STRING = re.compile(r"[a-z+]+://[^:@\s]+:[^@\s]+@", re.IGNORECASE)
_GENERIC_KEY_VAR = re.compile(
    r"^[ \t]*(?:export\s+)?"
    r"(?P<var>[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|CREDENTIALS)[A-Z_]*)"
    r"\s*[=:]\s*(?P<val>.+)",
    re.IGNORECASE | re.MULTILINE,
)


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().strip('"').strip("'")
    return not stripped or bool(_PLACEHOLDERS.match(stripped))


def _is_scannable(file: Path) -> bool:
    name = file.name
    # dotfiles like .env, .env.local, .env.production
    if name.startswith(".env"):
        return True
    return file.suffix in _SCANNED_EXTENSIONS


def _iter_files(path: Path):
    for item in path.rglob("*"):
        if any(part in _IGNORED_DIRS for part in item.parts):
            continue
        if item.is_file() and _is_scannable(item):
            yield item


class SecretScanner(BaseScanner):
    """Scans source files for hardcoded secrets and API keys."""

    def scan(self, path: Path) -> list[Finding]:
        """Scan the given path for hardcoded secrets.

        Args:
            path: Root directory to scan.

        Returns:
            List of findings for each detected secret.
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

        for i, line in enumerate(text.splitlines(), start=1):
            if _AWS_KEY.search(line):
                results.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=i,
                        rule_id="SECRET_AWS",
                        message="AWS access key detected",
                    )
                )

            if _PRIVATE_KEY.search(line):
                results.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=i,
                        rule_id="SECRET_PRIVATE_KEY",
                        message="Private key header detected",
                    )
                )

            if _CONN_STRING.search(line):
                results.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=i,
                        rule_id="SECRET_CONN_STRING",
                        message="Connection string with inline password detected",
                    )
                )

        if file.suffix in _GENERIC_KEY_EXTENSIONS or file.name.startswith(".env"):
            for match in _GENERIC_KEY_VAR.finditer(text):
                var = match.group("var")
                val = match.group("val").strip().strip('"').strip("'")
                if _is_placeholder(val):
                    continue
                line_number = text[: match.start()].count("\n") + 1
                results.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        file_path=rel,
                        line_number=line_number,
                        rule_id="SECRET_GENERIC",
                        message=f"Potential secret in variable {var!r}",
                    )
                )

        return results
