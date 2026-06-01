"""Tests for the config loader."""

import pytest

from envsafe.config import EnvSafeConfig, load_config


def test_default_config_when_no_file(tmp_project):
    config = load_config(tmp_project)
    assert isinstance(config, EnvSafeConfig)
    assert config.exclude == []
    assert config.rules.disable == []
    assert config.rules.severity_override == {}
    assert config.custom_patterns == []


def test_loads_yaml_config(tmp_project):
    (tmp_project / ".envsafe.yml").write_text("exclude:\n  - vendor/\nexclude:\n  - vendor/\n")
    config = load_config(tmp_project)
    assert isinstance(config, EnvSafeConfig)


def test_config_with_disabled_rules(tmp_project):
    (tmp_project / ".envsafe.yml").write_text(
        "rules:\n  disable:\n    - WEAK_PASSWORD_SHORT\n    - DOCKER_IMAGE_NO_TAG\n"
    )
    config = load_config(tmp_project)
    assert "WEAK_PASSWORD_SHORT" in config.rules.disable
    assert "DOCKER_IMAGE_NO_TAG" in config.rules.disable


def test_config_with_severity_override(tmp_project):
    (tmp_project / ".envsafe.yml").write_text(
        "rules:\n  severity_override:\n    DOCKER_IMAGE_NO_TAG: INFO\n"
    )
    config = load_config(tmp_project)
    assert config.rules.severity_override["DOCKER_IMAGE_NO_TAG"] == "INFO"


def test_config_with_custom_patterns(tmp_project):
    (tmp_project / ".envsafe.yml").write_text(
        "custom_patterns:\n"
        "  - name: CUSTOM_TOKEN\n"
        "    pattern: INTERNAL_[A-Z]+_TOKEN\n"
        "    severity: WARNING\n"
        "    message: Internal token found\n"
    )
    config = load_config(tmp_project)
    assert len(config.custom_patterns) == 1
    assert config.custom_patterns[0].name == "CUSTOM_TOKEN"
    assert config.custom_patterns[0].severity == "WARNING"


def test_config_with_exclude(tmp_project):
    (tmp_project / ".envsafe.yml").write_text("exclude:\n  - vendor/\n  - '*.min.js'\n")
    config = load_config(tmp_project)
    assert "vendor/" in config.exclude


def test_invalid_yaml_raises_value_error(tmp_project):
    (tmp_project / ".envsafe.yml").write_text("key: [\n  unclosed bracket\n")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(tmp_project)


def test_loads_envsafe_yaml_extension(tmp_project):
    (tmp_project / ".envsafe.yaml").write_text("exclude:\n  - dist/\n")
    config = load_config(tmp_project)
    assert "dist/" in config.exclude


def test_empty_yaml_returns_defaults(tmp_project):
    (tmp_project / ".envsafe.yml").write_text("")
    config = load_config(tmp_project)
    assert config.exclude == []
