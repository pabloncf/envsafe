"""Configuration loader for .envsafe.yml."""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class CustomPattern(BaseModel):
    """A user-defined regex pattern to detect custom secrets."""

    name: str
    pattern: str
    severity: str = "WARNING"
    message: str = "Custom pattern matched"


class RulesConfig(BaseModel):
    """Per-rule overrides."""

    disable: list[str] = Field(default_factory=list)
    severity_override: dict[str, str] = Field(default_factory=dict)


class EnvSafeConfig(BaseModel):
    """Top-level configuration schema for .envsafe.yml."""

    exclude: list[str] = Field(default_factory=list)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    custom_patterns: list[CustomPattern] = Field(default_factory=list)


_CONFIG_FILES = [".envsafe.yml", ".envsafe.yaml"]


def load_config(root: Path) -> EnvSafeConfig:
    """Load configuration from .envsafe.yml in the project root.

    Args:
        root: Project root directory to search for config file.

    Returns:
        Parsed EnvSafeConfig. Returns defaults if no file found.

    Raises:
        SystemExit: If the config file exists but is invalid YAML or fails schema validation.
    """
    import yaml  # lazy import — only needed when config is present

    for name in _CONFIG_FILES:
        config_path = root / name
        if config_path.exists():
            try:
                raw: Any = yaml.safe_load(config_path.read_text()) or {}
            except yaml.YAMLError as exc:
                raise ValueError(f"Invalid YAML in {name}: {exc}") from exc

            try:
                return EnvSafeConfig.model_validate(raw)
            except ValidationError as exc:
                raise ValueError(f"Invalid config in {name}: {exc}") from exc

    return EnvSafeConfig()
