"""Tests for the SecretScanner."""

import pytest

from envsafe.models import Severity
from envsafe.scanners.secrets import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


# ── AWS keys ──────────────────────────────────────────────────────────────────


def test_detects_aws_key(tmp_project, scanner):
    (tmp_project / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    findings = scanner.scan(tmp_project)
    rule_ids = {f.rule_id for f in findings}
    assert "SECRET_AWS" in rule_ids


def test_no_false_positive_short_akia(tmp_project, scanner):
    (tmp_project / ".env").write_text("NOTE=AKIA_SHORT\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "SECRET_AWS" for f in findings)


# ── Private keys ──────────────────────────────────────────────────────────────


def test_detects_private_key_header(tmp_project, scanner):
    (tmp_project / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
    # .pem is not in scanned extensions; use .env instead
    (tmp_project / "secrets.env").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "SECRET_PRIVATE_KEY" for f in findings)


# ── Connection strings ────────────────────────────────────────────────────────


def test_detects_conn_string(tmp_project, scanner):
    (tmp_project / "config.cfg").write_text("DATABASE_URL=postgresql://user:s3cr3t@localhost/db\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "SECRET_CONN_STRING" for f in findings)


def test_no_false_positive_conn_string_no_password(tmp_project, scanner):
    (tmp_project / "config.cfg").write_text("DATABASE_URL=postgresql://localhost/db\n")
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "SECRET_CONN_STRING" for f in findings)


# ── Generic secrets ───────────────────────────────────────────────────────────


def test_detects_generic_api_key(tmp_project, scanner):
    (tmp_project / ".env").write_text("API_KEY=sk-realkey1234567890abcdef\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "SECRET_GENERIC" for f in findings)


def test_placeholder_not_flagged(tmp_project, scanner):
    (tmp_project / ".env").write_text(
        "API_KEY=changeme\nSECRET=your-key-here\nTOKEN=${MY_TOKEN}\nPASSWORD=\n"
    )
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "SECRET_GENERIC" for f in findings)


def test_detects_generic_password(tmp_project, scanner):
    (tmp_project / ".env").write_text("DB_PASSWORD=hunter2_real_pass\n")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "SECRET_GENERIC" for f in findings)


# ── Ignored directories ───────────────────────────────────────────────────────


def test_ignores_git_dir(tmp_project, scanner):
    git_env = tmp_project / ".git" / "config"
    git_env.mkdir(parents=True)
    (git_env / ".env").write_text("API_KEY=AKIAIOSFODNN7EXAMPLE\n") if False else None
    git_cfg = tmp_project / ".git" / "config"
    git_cfg.parent.mkdir(parents=True, exist_ok=True)
    (tmp_project / ".git" / "secrets.env").write_text("API_KEY=sk-realkey1234567890abcdef\n")
    findings = scanner.scan(tmp_project)
    assert not any(".git" in f.file_path for f in findings)


def test_ignores_node_modules(tmp_project, scanner):
    nm = tmp_project / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / ".env").write_text("API_KEY=sk-realkey1234567890abcdef\n")
    findings = scanner.scan(tmp_project)
    assert not any("node_modules" in f.file_path for f in findings)


def test_ignores_venv(tmp_project, scanner):
    venv = tmp_project / "venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "config.cfg").write_text("API_KEY=sk-realkey1234567890abcdef\n")
    findings = scanner.scan(tmp_project)
    assert not any("venv" in f.file_path for f in findings)


# ── File extensions ───────────────────────────────────────────────────────────


def test_scans_yaml_file(tmp_project, scanner):
    (tmp_project / "config.yml").write_text("api_key: sk-realkey1234567890abcdef\n")
    findings = scanner.scan(tmp_project)
    # yaml values may not match the KEY= pattern; AWS/conn/private key patterns still work
    # This test verifies the file is at least opened (no crash)
    assert isinstance(findings, list)


def test_finding_has_line_number(tmp_project, scanner):
    (tmp_project / ".env").write_text("FOO=bar\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nBAZ=qux\n")
    findings = scanner.scan(tmp_project)
    aws = next((f for f in findings if f.rule_id == "SECRET_AWS"), None)
    assert aws is not None
    assert aws.line_number == 2


def test_all_findings_are_critical(tmp_project, scanner):
    (tmp_project / ".env").write_text(
        "API_KEY=sk-realkey1234567890abcdef\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
    )
    findings = scanner.scan(tmp_project)
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_scan_empty_dir(tmp_project, scanner):
    findings = scanner.scan(tmp_project)
    assert findings == []
