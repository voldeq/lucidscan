# LucidScan

[![CI](https://github.com/lucidscan/lucidscan/actions/workflows/ci.yml/badge.svg)](https://github.com/lucidscan/lucidscan/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/lucidscan/lucidscan/graph/badge.svg)](https://codecov.io/gh/lucidscan/lucidscan)
[![PyPI version](https://img.shields.io/pypi/v/lucidscan)](https://pypi.org/project/lucidscan/)
[![Python](https://img.shields.io/pypi/pyversions/lucidscan)](https://pypi.org/project/lucidscan/)
[![License](https://img.shields.io/github/license/lucidscan/lucidscan)](https://github.com/lucidscan/lucidscan/blob/main/LICENSE)

**The trust layer for AI-assisted development.**

LucidScan unifies linting, type checking, security scanning, testing, and coverage into a single pipeline that auto-configures for any project and integrates with AI coding tools like Claude Code and Cursor.

```
AI writes code → LucidScan checks → AI fixes → repeat
```

## Quick Start

```bash
# 1. Install LucidScan
pip install lucidscan

# 2. Set up your AI tools (Claude Code and/or Cursor)
lucidscan init --all

# 3. Restart your AI tool, then ask it:
#    "Autoconfigure LucidScan for this project"
```

That's it! Your AI assistant will analyze your codebase, ask you a few questions, and generate the `lucidscan.yml` configuration.

### Alternative: CLI Configuration

If you prefer to configure without AI:

```bash
lucidscan autoconfigure
```

### Running Scans

```bash
# Run the full quality pipeline
lucidscan scan --all

# Run specific checks
lucidscan scan --linting           # Linting (Ruff, ESLint, Biome)
lucidscan scan --type-checking     # Type checking (mypy, pyright, tsc)
lucidscan scan --sast              # Security code analysis (OpenGrep)
lucidscan scan --sca               # Dependency vulnerabilities (Trivy)
lucidscan scan --iac               # Infrastructure-as-Code (Checkov)
lucidscan scan --container         # Container image scanning (Trivy)
lucidscan scan --testing           # Run tests (pytest, Jest)
lucidscan scan --coverage          # Coverage analysis

# Auto-fix linting issues
lucidscan scan --linting --fix
```

### AI Tool Setup

#### Claude Code

```bash
lucidscan init --claude-code
```

This:
- Adds LucidScan to your Claude Code MCP configuration (`.mcp.json`)
- Creates `.claude/CLAUDE.md` with scan workflow instructions

Restart Claude Code to activate.

#### Cursor

```bash
lucidscan init --cursor
```

This:
- Adds LucidScan to Cursor's MCP configuration (`~/.cursor/mcp.json`)
- Creates `.cursor/rules/lucidscan.mdc` with auto-scan rules

#### All AI Tools

```bash
lucidscan init --all
```

Configures both Claude Code and Cursor.

## What It Checks

| Domain | Tools | What It Catches |
|--------|-------|-----------------|
| **Linting** | Ruff, ESLint, Biome, Checkstyle | Style issues, code smells |
| **Type Checking** | mypy, pyright, TypeScript | Type errors |
| **Security (SAST)** | OpenGrep | Code vulnerabilities |
| **Security (SCA)** | Trivy | Dependency vulnerabilities |
| **Security (IaC)** | Checkov | Infrastructure misconfigurations |
| **Security (Container)** | Trivy | Container image vulnerabilities |
| **Testing** | pytest, Jest, Karma (Angular), Playwright (E2E) | Test failures |
| **Coverage** | coverage.py, Istanbul | Coverage gaps |

All results are normalized to a common format.

## Configuration

LucidScan auto-detects your project. For custom settings, create `lucidscan.yml`:

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
# Configure AI tools (Claude Code, Cursor)
lucidscan init --claude-code             # Configure Claude Code
lucidscan init --cursor                  # Configure Cursor
lucidscan init --all                     # Configure all AI tools

# Auto-configure project (detect languages, generate lucidscan.yml)
lucidscan autoconfigure [--ci github|gitlab|bitbucket] [--non-interactive]

# Run quality pipeline
lucidscan scan [--linting] [--type-checking] [--sca] [--sast] [--iac] [--container] [--testing] [--coverage] [--all]
lucidscan scan [--fix] [--stream] [--format table|json|sarif|summary]
lucidscan scan [--fail-on critical|high|medium|low]

# Server mode
lucidscan serve --mcp                    # Run MCP server
lucidscan serve --watch                  # Watch mode with auto-checking

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
git clone https://github.com/lucidscan/lucidscan.git
cd lucidscan
pip install -e ".[dev]"
pytest tests/
```

## Documentation

- [LLM Reference Documentation](docs/help.md) - For AI agents and detailed reference
- [Full Specification](docs/main.md)
- [Roadmap](docs/roadmap.md)

## License

Apache 2.0
