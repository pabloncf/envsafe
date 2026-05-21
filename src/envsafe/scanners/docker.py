"""Docker Compose scanner — detects insecure container configuration."""

import re
from pathlib import Path

from envsafe.models import Finding, Severity
from envsafe.scanners.base import BaseScanner

_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}

_SECRET_VARS = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[A-Z_]*\s*=\s*(?P<val>[^\s$#{}][^\s]*)",
    re.IGNORECASE,
)
_IMAGE_NO_TAG = re.compile(r"^\s*image:\s*(?P<img>[a-z0-9/_.-]+)\s*$", re.IGNORECASE)
_PRIVILEGED = re.compile(r"privileged:\s*true", re.IGNORECASE)

_PLACEHOLDER = re.compile(
    r"^(changeme|xxx+|your[_-]?secret|dummy|example|placeholder|none|null|\$\{.+\}|<.+>)$",
    re.IGNORECASE,
)


def _is_placeholder(val: str) -> bool:
    return not val or bool(_PLACEHOLDER.match(val.strip()))


class DockerScanner(BaseScanner):
    """Scans Docker Compose files for insecure configuration."""

    def scan(self, path: Path) -> list[Finding]:
        """Scan Docker Compose files under the given path.

        Args:
            path: Root directory to scan.

        Returns:
            List of security findings in Compose files.
        """
        findings: list[Finding] = []
        for name in _COMPOSE_NAMES:
            compose_file = path / name
            if compose_file.exists():
                findings.extend(self._scan_file(compose_file, path))
        return findings

    def _scan_file(self, file: Path, root: Path) -> list[Finding]:
        try:
            text = file.read_text()
        except OSError:
            return []

        rel = str(file.relative_to(root))
        results: list[Finding] = []

        for i, line in enumerate(text.splitlines(), start=1):
            for m in _SECRET_VARS.finditer(line):
                val = m.group("val").strip().strip('"').strip("'")
                if not _is_placeholder(val):
                    results.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            file_path=rel,
                            line_number=i,
                            rule_id="DOCKER_SECRET_INLINE",
                            message=f"Hardcoded secret in Compose environment block (line {i})",
                        )
                    )

            if _PRIVILEGED.search(line):
                results.append(
                    Finding(
                        severity=Severity.WARNING,
                        file_path=rel,
                        line_number=i,
                        rule_id="DOCKER_PRIVILEGED",
                        message="Container runs with privileged: true — grants full host access",
                    )
                )

            m = _IMAGE_NO_TAG.match(line)
            if m:
                img = m.group("img")
                if ":" not in img:
                    results.append(
                        Finding(
                            severity=Severity.WARNING,
                            file_path=rel,
                            line_number=i,
                            rule_id="DOCKER_IMAGE_NO_TAG",
                            message=f"Image '{img}' has no version tag — pin to a specific tag",
                        )
                    )

        return results
