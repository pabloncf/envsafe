"""Tests for the WeakCredentialScanner."""

import pytest

from envsafe.models import Severity
from envsafe.scanners.weak_credentials import WeakCredentialScanner


@pytest.fixture
def scanner():
    return WeakCredentialScanner()


def test_detects_common_weak_password(tmp_project, scanner):
    (tmp_project / ".env").write_text("DB_PASSWORD=password\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "WEAK_PASSWORD_COMMON" for f in findings)
    assert any(f.severity == Severity.WARNING for f in findings)


def test_detects_admin_password(tmp_project, scanner):
    (tmp_project / ".env").write_text("APP_SECRET=admin\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "WEAK_PASSWORD_COMMON" for f in findings)


def test_detects_short_password(tmp_project, scanner):
    (tmp_project / ".env").write_text("DB_PASSWORD=ab12\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "WEAK_PASSWORD_SHORT" for f in findings)


def test_strong_password_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text("DB_PASSWORD=Str0ng!Pa$$w0rd\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id in {"WEAK_PASSWORD_COMMON", "WEAK_PASSWORD_SHORT"} for f in findings)


def test_env_var_no_password(tmp_project, scanner):
    (tmp_project / ".env").write_text("APP_NAME=myapp\nDEBUG=true\n")
    findings = scanner.scan(tmp_project)
    assert findings == []


def test_empty_value_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text("DB_PASSWORD=\n")
    findings = scanner.scan(tmp_project)
    assert findings == []


def test_env_var_reference_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text("DB_PASSWORD=${REAL_PASS}\n")
    findings = scanner.scan(tmp_project)
    assert findings == []


def test_scans_cfg_file(tmp_project, scanner):
    (tmp_project / "app.cfg").write_text("[db]\npassword=admin\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "WEAK_PASSWORD_COMMON" for f in findings)


def test_no_files_no_findings(tmp_project, scanner):
    findings = scanner.scan(tmp_project)
    assert findings == []


def test_finding_has_line_number(tmp_project, scanner):
    (tmp_project / ".env").write_text("FOO=bar\nDB_PASSWORD=admin\n")
    findings = scanner.scan(tmp_project)
    weak = next((f for f in findings if f.rule_id == "WEAK_PASSWORD_COMMON"), None)
    assert weak is not None
    assert weak.line_number == 2
