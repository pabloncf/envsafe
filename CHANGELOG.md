# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-05

### Added

- `SecretScanner`: detects AWS keys, private key headers, connection strings with inline passwords, and generic hardcoded secrets in KEY/SECRET/TOKEN/PASSWORD variables
- `GitignoreScanner`: verifies `.env` and private key files are covered by `.gitignore`
- `DockerScanner`: detects hardcoded secrets in Compose `environment:` blocks, `privileged: true`, and images without version tags
- `WeakCredentialScanner`: detects common weak passwords and passwords shorter than 8 characters
- `EnvExampleScanner`: checks for `.env.example` presence and warns when it contains real values
- CLI with `scan` command, `--json`, `--strict`, `--exclude`, `--rules`, and `--version` flags
- YAML-based configuration via `.envsafe.yml` with rule disabling, severity overrides, and custom patterns
- Pre-commit hook integration via `.pre-commit-hooks.yaml`
