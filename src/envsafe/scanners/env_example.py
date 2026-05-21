"""Env example scanner — checks for .env.example presence and safety."""

import re
from pathlib import Path

from envsafe.models import Finding, Severity
from envsafe.scanners.base import BaseScanner

_PLACEHOLDER = re.compile(
    r"^(changeme|xxx+|your[_-]?[\w-]+|dummy|example|placeholder|none|null|true|false|0|1|\$\{.+\}|<.+>|)$",
    re.IGNORECASE,
)

_KEY_LINE = re.compile(
    r"^[ \t]*(?:export\s+)?(?P<key>[A-Z_][A-Z0-9_]*)\s*=\s*(?P<val>.*)", re.IGNORECASE
)


def _parse_env(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        m = _KEY_LINE.match(line)
        if m:
            result[m.group("key").upper()] = m.group("val").strip().strip('"').strip("'")
    return result


def _is_real_value(val: str) -> bool:
    return bool(val) and not _PLACEHOLDER.match(val)


class EnvExampleScanner(BaseScanner):
    """Ensures .env.example exists and contains only placeholder values."""

    def scan(self, path: Path) -> list[Finding]:
        """Check .env.example coverage and safety.

        Args:
            path: Root directory to scan.

        Returns:
            List of findings about .env.example status.
        """
        findings: list[Finding] = []
        env_path = path / ".env"
        example_path = path / ".env.example"

        if not env_path.exists():
            return findings

        if not example_path.exists():
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    file_path=".env.example",
                    rule_id="ENV_EXAMPLE_MISSING",
                    message=".env.example not found — add one so teammates know required variables",
                )
            )
            return findings

        example_vars = _parse_env(example_path.read_text(errors="replace"))
        for key, val in example_vars.items():
            if _is_real_value(val):
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        file_path=".env.example",
                        rule_id="ENV_EXAMPLE_HAS_REAL_VALUES",
                        message=f".env.example contains a real (non-placeholder) value for {key!r}",
                    )
                )

        return findings
