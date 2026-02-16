# Getting Started with LucidShark for Python Projects

This guide walks you through setting up LucidShark on a Python project, from installation to your first scan.

## Prerequisites

- **Python 3.10+** (check with `python --version`)
- **pip** or **pipx** for installation
- A Python project with a `pyproject.toml`, `setup.py`, or `requirements.txt`

## Install LucidShark

```bash
pip install lucidshark
```

Or use the standalone binary (no Python required):

```bash
curl -fsSL https://raw.githubusercontent.com/lucidshark-code/lucidshark/main/install.sh | bash
```

Verify the installation:

```bash
lucidshark --version
# lucidshark 0.5.25
```

## Auto-Configure Your Project

Run autoconfigure from your project root. LucidShark detects your languages, frameworks, and existing tools, then generates a `lucidshark.yml` config file.

```bash
lucidshark autoconfigure
```

You will see output like:

```
Analyzing project...

Detected:
  Languages:    Python 3.12
  Frameworks:   Flask
  Testing:      pytest
  Tools:        ruff, mypy

Configuration:
  Linter:       ruff (detected)
  Type checker: mypy (detected)
  Security:     trivy, opengrep
  Test runner:  pytest (detected)
  Duplication:  duplo (threshold: 10%)

? Proceed with this configuration? Yes

Generating configuration...
  Created lucidshark.yml

Done! Next steps:
  1. Review the generated lucidshark.yml
  2. Run 'lucidshark scan --all' to test the configuration
```

Use `-y` to skip prompts: `lucidshark autoconfigure -y`

## Review the Generated Config

Open `lucidshark.yml`. For a typical Python project it looks like this:

```yaml
version: 1

project:
  name: my-flask-app
  languages: [python]

pipeline:
  linting:
    enabled: true
    tools:
      - name: ruff

  type_checking:
    enabled: true
    tools:
      - name: mypy

  security:
    enabled: true
    tools:
      - name: trivy
        domains: [sca]
      - name: opengrep
        domains: [sast]

  testing:
    enabled: true
    tools:
      - name: pytest

  coverage:
    enabled: true
    tools:
      - name: coverage_py
    threshold: 80

  duplication:
    enabled: true
    threshold: 10.0

fail_on:
  linting: error
  type_checking: error
  security: high
  testing: any
  coverage: below_threshold
  duplication: above_threshold

ignore:
  - "**/__pycache__/**"
  - "**/.venv/**"
  - "**/.pytest_cache/**"
  - "**/.mypy_cache/**"
```

Key sections:
- **pipeline** -- Which tools to run. Each domain (linting, type checking, etc.) can be toggled independently.
- **fail_on** -- When LucidShark should return a non-zero exit code. `error` means any linting error fails the scan; `high` means only high/critical security findings cause failure.
- **ignore** -- Glob patterns for files to skip (gitignore-style syntax).

You can also skip the config file and use a preset instead:

```bash
lucidshark scan --preset python-strict
```

## Run Your First Scan

Run the full quality pipeline:

```bash
lucidshark scan --all
```

Example output when issues are found:

```
Total issues: 6

By severity:
  HIGH: 1
  MEDIUM: 3
  LOW: 2

By scanner domain:
  LINTING: 3
  TYPE_CHECKING: 2
  SAST: 1

Scan duration: 2847ms
```

For a detailed per-issue breakdown, use `--format table`:

```bash
lucidshark scan --all --format table
```

```
SEVERITY   ID                   DEPENDENCY                               TITLE
----------------------------------------------------------------------------------------------------
HIGH       hardcoded-password   -                                        Hardcoded credentials in config.py:23
MEDIUM     E501                 -                                        Line too long (127 > 88)
MEDIUM     assignment           -                                        Incompatible types in assignment
MEDIUM     F401                 -                                        Unused import 'os'
LOW        W291                 -                                        Trailing whitespace
LOW        D103                 -                                        Missing function docstring

----------------------------------------------------------------------------------------------------
Total: 6 issues
By severity: high: 1, medium: 3, low: 2
```

When everything passes:

```
No issues found.
```

## Understanding Results

Each issue has:
- **Severity** -- `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
- **Domain** -- Which check found it (`LINTING`, `TYPE_CHECKING`, `SAST`, `SCA`, etc.)
- **ID/Rule** -- The specific rule that triggered (e.g., `E501` for Ruff, `assignment` for mypy)
- **Location** -- File and line number

LucidShark returns exit code `1` when issues exceed your `fail_on` thresholds. Exit code `0` means all checks passed.

## Auto-Fix Linting Issues

Ruff supports auto-fixing many linting issues. Run:

```bash
lucidshark scan --linting --fix
```

This modifies files in place. Only linting issues are auto-fixable -- type errors and security findings require manual fixes.

## Set Up AI Integration

LucidShark integrates with Claude Code and Cursor via MCP (Model Context Protocol). Your AI assistant can run scans, read results, and fix issues directly.

### Claude Code

```bash
lucidshark init --claude-code
```

Restart Claude Code, then ask it: "Autoconfigure LucidShark for this project" or "Run a LucidShark scan."

### Cursor

```bash
lucidshark init --cursor
```

### Both

```bash
lucidshark init --all
```

## Common Python Tips

### Suppressing Linting Warnings

```python
# Suppress a specific Ruff rule on one line
x = 1  # noqa: E501

# Suppress all rules on a line
x = 1  # noqa

# Suppress for entire file (place at top)
# ruff: noqa: E501
```

### Suppressing Type Errors

```python
# mypy: suppress on a line
result: int = get_value()  # type: ignore[assignment]

# pyright: suppress on a line
result: int = get_value()  # pyright: ignore[reportAssignmentType]
```

### Skipping Tests

```python
import pytest

@pytest.mark.skip(reason="Not implemented yet")
def test_feature():
    pass

@pytest.mark.xfail(reason="Known bug #123")
def test_buggy():
    pass
```

### Suppressing Security Findings

```python
password = os.getenv("DB_PASS")  # nosemgrep: hardcoded-password
```

See [Ignore Patterns](ignore-patterns.md) for the full reference.

## Adding to CI

Add LucidShark to your CI pipeline to enforce quality on every push:

```yaml
# .github/workflows/quality.yml
name: Quality
on: [push, pull_request]

jobs:
  lucidshark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install lucidshark
      - run: lucidshark scan --all --all-files
```

LucidShark exits with code `1` when issues exceed thresholds, which fails the CI job.

## Next Steps

- [LLM Reference](help.md) -- Full CLI and configuration reference
- [Ignore Patterns](ignore-patterns.md) -- Detailed guide for excluding files and findings
- [Full Specification](main.md) -- Architecture and design documentation
