"""Tests for the EnvExampleScanner."""

import pytest

from envsafe.models import Severity
from envsafe.scanners.env_example import EnvExampleScanner


@pytest.fixture
def scanner():
    return EnvExampleScanner()


def test_no_env_no_findings(tmp_project, scanner):
    findings = scanner.scan(tmp_project)
    assert findings == []


def test_env_without_example(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=value\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "ENV_EXAMPLE_MISSING" for f in findings)
    assert any(f.severity == Severity.INFO for f in findings)


def test_env_with_example(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=realvalue\n")
    (tmp_project / ".env.example").write_text("KEY=your-key-here\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "ENV_EXAMPLE_MISSING" for f in findings)
    assert not any(f.rule_id == "ENV_EXAMPLE_HAS_REAL_VALUES" for f in findings)


def test_example_with_real_value(tmp_project, scanner):
    (tmp_project / ".env").write_text("KEY=realvalue\n")
    (tmp_project / ".env.example").write_text("KEY=sk-actual-real-key-12345\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "ENV_EXAMPLE_HAS_REAL_VALUES" for f in findings)
    assert any(f.severity == Severity.WARNING for f in findings)


def test_example_with_placeholder_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text("SECRET=realval123\n")
    (tmp_project / ".env.example").write_text("SECRET=your-secret-here\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "ENV_EXAMPLE_HAS_REAL_VALUES" for f in findings)


def test_example_with_env_var_reference_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text("SECRET=realval123\n")
    (tmp_project / ".env.example").write_text("SECRET=${MY_SECRET}\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "ENV_EXAMPLE_HAS_REAL_VALUES" for f in findings)


def test_example_empty_value_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text("SECRET=realval123\n")
    (tmp_project / ".env.example").write_text("SECRET=\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "ENV_EXAMPLE_HAS_REAL_VALUES" for f in findings)
