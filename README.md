# LucidScan

[![CI](https://github.com/voldeq/lucidscan/actions/workflows/ci.yml/badge.svg)](https://github.com/voldeq/lucidscan/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/voldeq/lucidscan/graph/badge.svg)](https://codecov.io/gh/voldeq/lucidscan)
[![PyPI version](https://img.shields.io/pypi/v/lucidscan)](https://pypi.org/project/lucidscan/)
[![Python](https://img.shields.io/pypi/pyversions/lucidscan)](https://pypi.org/project/lucidscan/)
[![License](https://img.shields.io/github/license/voldeq/lucidscan)](https://github.com/voldeq/lucidscan/blob/main/LICENSE)

**The trust layer for AI-assisted development.**

LucidScan is a unified code quality pipeline that auto-configures linting, type checking, security scanning, testing, and coverage — then integrates with AI coding tools like Claude Code and Cursor to create an automated feedback loop.

```
AI writes code → LucidScan checks → LucidScan tells AI what to fix → AI fixes → repeat
```

## Why LucidScan?

AI coding assistants generate code fast, but developers can't blindly trust it. The current workflow is painful:

1. AI writes code
2. You run ESLint... then Ruff... then mypy... then Trivy...
3. You copy error messages back to the AI
4. AI fixes, you re-run everything
5. Repeat 5-10 times

**LucidScan fixes this** by unifying all quality tools behind one command and feeding results directly back to AI agents.

## Quick Start

```bash
pip install lucidscan

# Auto-configure for your project
lucidscan init

# Run the full quality pipeline
lucidscan scan

# Auto-fix what's possible
lucidscan scan --fix
```

## What It Does

One command runs your entire quality pipeline:

| Domain | Tools | What It Catches |
|--------|-------|-----------------|
| **Linting** | Ruff, ESLint, Biome, Checkstyle | Style issues, code smells |
| **Type Checking** | mypy, pyright, TypeScript | Type errors |
| **Security** | Trivy, OpenGrep, Checkov | Vulnerabilities, misconfigs |
| **Testing** | pytest, Jest | Test failures (planned) |
| **Coverage** | coverage.py, Istanbul | Coverage gaps (planned) |

All results normalized to a common format. One exit code for CI.

## The `init` Command

```bash
lucidscan init
```

LucidScan analyzes your codebase and asks targeted questions:

```
Detected: Python 3.11, FastAPI, pytest

? Linter: [Ruff (recommended)] / Skip
? Type checker: [mypy (recommended)] / pyright / Skip
? Security scanner: [Trivy + OpenGrep (recommended)] / Trivy only / Skip
? CI platform: [GitHub Actions (detected)] / GitLab / Bitbucket / Skip
```

Then generates:
- `lucidscan.yml` — unified configuration
- `.github/workflows/lucidscan.yml` — CI pipeline (or GitLab/Bitbucket equivalent)

## AI Integration

LucidScan integrates with AI coding tools to create an automated feedback loop.

### Claude Code / Cursor (MCP Server)

```bash
lucidscan serve --mcp
```

Configure in your AI tool to give it access to quality checks:

```json
{
  "mcpServers": {
    "lucidscan": {
      "command": "lucidscan",
      "args": ["serve", "--mcp"]
    }
  }
}
```

The AI can now:
- Run quality checks on code it writes
- Get structured fix instructions
- Apply fixes automatically

### Output for AI Agents

```bash
lucidscan scan --format ai
```

Returns actionable instructions:

```json
{
  "instructions": [
    {
      "action": "FIX_SECURITY_VULNERABILITY",
      "file": "src/auth.py",
      "line": 23,
      "problem": "Hardcoded password detected",
      "fix_steps": [
        "Replace with os.environ.get('DB_PASSWORD')",
        "Add DB_PASSWORD to .env.example"
      ]
    }
  ]
}
```

## CI Integration

### GitHub Actions

```yaml
name: Quality

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install lucidscan
      - run: lucidscan scan --ci
```

### GitLab CI

```yaml
lucidscan:
  image: python:3.11
  script:
    - pip install lucidscan
    - lucidscan scan --ci
```

### With SARIF Upload (GitHub Code Scanning)

```yaml
- run: lucidscan scan --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Configuration

`lucidscan.yml`:

```yaml
version: 1

pipeline:
  linting:
    enabled: true
    tools:
      - name: ruff

  type_checking:
    enabled: true
    tools:
      - name: mypy
        strict: true

  security:
    enabled: true
    tools:
      - name: trivy
      - name: opengrep

  testing:
    enabled: true
    tools:
      - name: pytest

  coverage:
    enabled: true
    threshold: 80

fail_on:
  linting: error
  security: high
  testing: any

ignore:
  - "**/node_modules/**"
  - "**/.venv/**"
```

## CLI Reference

```bash
# Initialize project
lucidscan init [--ci github|gitlab|bitbucket] [--non-interactive]

# Run quality pipeline
lucidscan scan [--lint] [--type-check] [--sca] [--sast] [--iac] [--all]
lucidscan scan [--fix] [--format table|json|sarif|summary]

# Start server for AI integration (planned)
lucidscan serve [--mcp] [--watch]

# Show status
lucidscan status [--tools]
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Issues found above threshold |
| 2 | Tool execution error |
| 3 | Configuration error |

## Development

```bash
git clone https://github.com/voldeq/lucidscan.git
cd lucidscan
pip install -e ".[dev]"
pytest tests/
```

## Documentation

- [Full Specification](docs/main.md)
- [Roadmap](docs/roadmap.md)
- [CI Integration Guide](docs/ci-integration.md)
- [Ignore Patterns](docs/ignore-patterns.md)

## License

Apache 2.0
