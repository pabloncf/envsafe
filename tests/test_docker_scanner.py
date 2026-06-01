"""Tests for the DockerScanner."""

import pytest

from envsafe.models import Severity
from envsafe.scanners.docker import DockerScanner

COMPOSE_TEMPLATE = """\
version: "3.9"
services:
  db:
    image: {image}
    environment:
      {env_line}
    {privileged}
"""


@pytest.fixture
def scanner():
    return DockerScanner()


def _write_compose(tmp_project, content: str, filename: str = "docker-compose.yml"):
    (tmp_project / filename).write_text(content)


# ── Secret inline ─────────────────────────────────────────────────────────────


def test_detects_secret_inline(tmp_project, scanner):
    _write_compose(
        tmp_project,
        COMPOSE_TEMPLATE.format(
            image="postgres:16", env_line="POSTGRES_PASSWORD=supersecret123", privileged=""
        ),
    )
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "DOCKER_SECRET_INLINE" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_placeholder_not_flagged(tmp_project, scanner):
    _write_compose(
        tmp_project,
        COMPOSE_TEMPLATE.format(
            image="postgres:16", env_line="POSTGRES_PASSWORD=${DB_PASSWORD}", privileged=""
        ),
    )
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "DOCKER_SECRET_INLINE" for f in findings)


def test_placeholder_changeme_not_flagged(tmp_project, scanner):
    _write_compose(
        tmp_project,
        COMPOSE_TEMPLATE.format(
            image="postgres:16", env_line="POSTGRES_PASSWORD=changeme", privileged=""
        ),
    )
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "DOCKER_SECRET_INLINE" for f in findings)


# ── Privileged ────────────────────────────────────────────────────────────────


def test_detects_privileged(tmp_project, scanner):
    content = "version: '3'\nservices:\n  app:\n    image: alpine:3\n    privileged: true\n"
    _write_compose(tmp_project, content)
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "DOCKER_PRIVILEGED" for f in findings)
    assert any(f.severity == Severity.WARNING for f in findings)


def test_no_privileged_when_false(tmp_project, scanner):
    content = "version: '3'\nservices:\n  app:\n    image: alpine:3\n    privileged: false\n"
    _write_compose(tmp_project, content)
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "DOCKER_PRIVILEGED" for f in findings)


# ── Image no tag ──────────────────────────────────────────────────────────────


def test_detects_image_no_tag(tmp_project, scanner):
    content = "version: '3'\nservices:\n  db:\n    image: postgres\n"
    _write_compose(tmp_project, content)
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "DOCKER_IMAGE_NO_TAG" for f in findings)
    assert any(f.severity == Severity.WARNING for f in findings)


def test_image_with_tag_not_flagged(tmp_project, scanner):
    content = "version: '3'\nservices:\n  db:\n    image: postgres:16\n"
    _write_compose(tmp_project, content)
    findings = scanner.scan(tmp_project)
    assert not any(f.rule_id == "DOCKER_IMAGE_NO_TAG" for f in findings)


# ── Multiple compose file names ───────────────────────────────────────────────


def test_scans_compose_yaml(tmp_project, scanner):
    content = "version: '3'\nservices:\n  db:\n    image: mysql\n"
    _write_compose(tmp_project, content, filename="compose.yaml")
    findings = scanner.scan(tmp_project)
    assert any(f.rule_id == "DOCKER_IMAGE_NO_TAG" for f in findings)


def test_no_compose_file_no_findings(tmp_project, scanner):
    findings = scanner.scan(tmp_project)
    assert findings == []
