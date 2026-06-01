"""Tests for the GitignoreScanner."""

import pytest

from envsafe.models import Severity
from envsafe.scanners.gitignore import GitignoreScanner


@pytest.fixture
def scanner():
    return GitignoreScanner()


def test_no_env_no_findings(tmp_project, scanner):
    findings = scanner.scan(tmp_project)
    assert findings == []


def test_env_exists_but_no_gitignore(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "GITIGNORE_MISSING" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_env_not_in_gitignore(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    (tmp_project / ".gitignore").write_text("*.log\n__pycache__/\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "GITIGNORE_ENV_EXPOSED" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_env_in_gitignore(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    (tmp_project / ".gitignore").write_text(".env\n*.pem\n*.key\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "GITIGNORE_ENV_EXPOSED" for f in findings)
    assert not any(f.rule_id == "GITIGNORE_MISSING" for f in findings)


def test_env_star_pattern_covers_env(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    (tmp_project / ".gitignore").write_text(".env*\n*.pem\n*.key\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "GITIGNORE_ENV_EXPOSED" for f in findings)


def test_missing_key_files_in_gitignore(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    (tmp_project / ".gitignore").write_text(".env\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "GITIGNORE_KEYS_EXPOSED" for f in findings)
    assert any(f.severity == Severity.WARNING for f in findings)


def test_pem_covered(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    (tmp_project / ".gitignore").write_text(".env\n*.pem\n*.key\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "GITIGNORE_KEYS_EXPOSED" for f in findings)


def test_gitignore_with_comments_and_blanks(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    (tmp_project / ".gitignore").write_text(
        "# Python\n\n__pycache__/\n# Secrets\n.env\n*.pem\n*.key\n"
    )
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id in {"GITIGNORE_ENV_EXPOSED", "GITIGNORE_MISSING"} for f in findings)
