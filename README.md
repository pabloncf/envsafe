# envsafe

[![PyPI version](https://badge.fury.io/py/envsafe.svg)](https://badge.fury.io/py/envsafe)
[![Coverage](https://codecov.io/gh/pabloncf/envsafe/branch/main/graph/badge.svg)](https://codecov.io/gh/pabloncf/envsafe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A security audit CLI for environment variables and configuration files. Detects hardcoded secrets, misconfigured `.gitignore`, weak credentials, and insecure Docker Compose files.

## Installation

```bash
pip install envsafe
```

## Quick start

```bash
# Scan current directory
envsafe scan .

# Output as JSON (for CI pipelines)
envsafe scan . --json

# Exit with code 1 on CRITICAL findings
envsafe scan . --strict

# Exclude paths
envsafe scan . --exclude "vendor/*" --exclude "*.min.js"

# Run specific scanners only
envsafe scan . --rules secrets,gitignore

# Show version
envsafe --version
```

### Example output

```
╭─────────────────────╮
│  envsafe            │
╰─────────────────────╯

                 .env
┌──────────────────┬──────────────────┬──────┬────────────────────────────────┐
│ Severity         │ Rule             │ Line │ Message                        │
├──────────────────┼──────────────────┼──────┼────────────────────────────────┤
│ 🔴 CRITICAL      │ SECRET_AWS       │  3   │ AWS access key detected        │
│ 🟡 WARNING       │ WEAK_PASSWORD_… │  7   │ Common weak password detected  │
└──────────────────┴──────────────────┴──────┴────────────────────────────────┘

Found 1 critical, 1 warnings, 0 info
```

## Configuration

Create `.envsafe.yml` in your project root:

```yaml
exclude:
  - "vendor/"
  - "*.min.js"

rules:
  disable:
    - WEAK_PASSWORD_SHORT
  severity_override:
    DOCKER_IMAGE_NO_TAG: INFO

custom_patterns:
  - name: INTERNAL_TOKEN
    pattern: "INTERNAL_[A-Z]+_TOKEN"
    severity: WARNING
    message: "Internal token found in source"
```

## Pre-commit integration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pabloncf/envsafe
    rev: v0.1.0
    hooks:
      - id: envsafe
```

## Available rules

| Rule ID                  | Scanner          | Severity | Description                                              |
|--------------------------|------------------|----------|----------------------------------------------------------|
| `SECRET_AWS`             | secrets          | CRITICAL | AWS access key (`AKIA...`) detected                     |
| `SECRET_PRIVATE_KEY`     | secrets          | CRITICAL | Private key header detected                             |
| `SECRET_CONN_STRING`     | secrets          | CRITICAL | Connection string with inline password                  |
| `SECRET_GENERIC`         | secrets          | CRITICAL | Hardcoded value in KEY/SECRET/TOKEN/PASSWORD variable   |
| `GITIGNORE_MISSING`      | gitignore        | CRITICAL | `.gitignore` not found but `.env` exists                |
| `GITIGNORE_ENV_EXPOSED`  | gitignore        | CRITICAL | `.env` not covered by `.gitignore`                      |
| `GITIGNORE_KEYS_EXPOSED` | gitignore        | WARNING  | Private key files not covered by `.gitignore`           |
| `DOCKER_SECRET_INLINE`   | docker           | CRITICAL | Hardcoded secret in Compose `environment:` block        |
| `DOCKER_PRIVILEGED`      | docker           | WARNING  | Container uses `privileged: true`                       |
| `DOCKER_IMAGE_NO_TAG`    | docker           | WARNING  | Docker image has no version tag                         |
| `WEAK_PASSWORD_COMMON`   | weak             | WARNING  | Common weak password (e.g., `password`, `admin`)        |
| `WEAK_PASSWORD_SHORT`    | weak             | WARNING  | Password shorter than 8 characters                      |
| `ENV_EXAMPLE_MISSING`    | env-example      | INFO     | `.env.example` not found                                |
| `ENV_EXAMPLE_HAS_REAL_VALUES` | env-example | WARNING | `.env.example` contains non-placeholder values         |

## Contributing

1. Fork the repo and create your branch from `main`
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Write tests for any new scanner or rule
4. Ensure `pytest` and `ruff check` pass
5. Submit a pull request

## License

MIT — see [LICENSE](LICENSE) for details.
