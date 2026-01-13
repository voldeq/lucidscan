# CI Integration Guide

LucidScan integrates seamlessly with all major CI/CD platforms. This guide covers setup, common patterns, and best practices for running your unified quality pipeline in CI.

## Quick Start

The fastest way to add LucidScan to your project:

```bash
lucidscan autoconfigure --ci github   # or gitlab, bitbucket
```

This generates both `lucidscan.yml` (configuration) and the appropriate CI workflow file.

### Manual Setup

If you prefer manual setup:

**GitHub Actions:**
```yaml
- run: pip install lucidscan
- run: lucidscan scan --ci
```

**GitLab CI:**
```yaml
lucidscan:
  script:
    - pip install lucidscan
    - lucidscan scan --ci
```

**Bitbucket Pipelines:**
```yaml
- step:
    script:
      - pip install lucidscan
      - lucidscan scan --ci
```

---

## GitHub Actions

### Basic Setup

```yaml
name: Quality

on:
  push:
    branches: [main]
  pull_request:

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install LucidScan
        run: pip install lucidscan

      - name: Run quality checks
        run: lucidscan scan --ci
```

### With SARIF Upload (GitHub Code Scanning)

```yaml
name: Quality

on:
  push:
    branches: [main]
  pull_request:

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install lucidscan

      - name: Run LucidScan
        run: lucidscan scan --ci --format sarif --output results.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Running Specific Domains

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install lucidscan
      - run: lucidscan scan --domain linting --ci

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install lucidscan
      - run: lucidscan scan --domain security --ci

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install lucidscan
      - run: lucidscan scan --domain testing --ci
```

### Tiered Policy by Branch

```yaml
jobs:
  pr-checks:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install lucidscan
      - run: lucidscan scan --ci --fail-on high

  release-checks:
    if: startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install lucidscan
      - run: lucidscan scan --ci --fail-on medium
```

---

## GitLab CI

### Basic Setup

Add to your `.gitlab-ci.yml`:

```yaml
stages:
  - quality

lucidscan:
  stage: quality
  image: python:3.11
  script:
    - pip install lucidscan
    - lucidscan scan --ci
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Using the Template

Include the LucidScan template for pre-configured jobs:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/voldeq/lucidscan/main/ci-templates/gitlab-ci.yml'

variables:
  LUCIDSCAN_FAIL_ON: "high"
```

### Parallel Domain Scanning

```yaml
stages:
  - quality

.lucidscan-base:
  image: python:3.11
  before_script:
    - pip install lucidscan

lucidscan-lint:
  extends: .lucidscan-base
  stage: quality
  script:
    - lucidscan scan --domain linting --ci

lucidscan-security:
  extends: .lucidscan-base
  stage: quality
  script:
    - lucidscan scan --domain security --ci

lucidscan-test:
  extends: .lucidscan-base
  stage: quality
  script:
    - lucidscan scan --domain testing --ci
```

### Container Scanning

```yaml
build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

scan-container:
  stage: quality
  image: python:3.11
  script:
    - pip install lucidscan
    - lucidscan scan --domain security --image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  needs:
    - build
```

---

## Bitbucket Pipelines

### Basic Setup

Add to your `bitbucket-pipelines.yml`:

```yaml
image: python:3.11

pipelines:
  default:
    - step:
        name: Quality Checks
        script:
          - pip install lucidscan
          - lucidscan scan --ci

  pull-requests:
    '**':
      - step:
          name: Quality Checks
          script:
            - pip install lucidscan
            - lucidscan scan --ci --fail-on high
```

### Parallel Scanning

```yaml
pipelines:
  default:
    - parallel:
        - step:
            name: Linting
            script:
              - pip install lucidscan
              - lucidscan scan --domain linting --ci
        - step:
            name: Security
            script:
              - pip install lucidscan
              - lucidscan scan --domain security --ci
        - step:
            name: Tests
            script:
              - pip install lucidscan
              - lucidscan scan --domain testing --ci
```

---

## Exit Codes

LucidScan uses exit codes to communicate results:

| Code | Meaning | CI Behavior |
|------|---------|-------------|
| `0` | All checks passed (or below threshold) | Pass |
| `1` | Issues found at or above threshold | Fail |
| `2` | Tool execution error | Fail |
| `3` | Configuration error | Fail |
| `4` | Bootstrap/installation failure | Fail |

---

## Fail Thresholds

### By Domain

Configure thresholds per domain in `lucidscan.yml`:

```yaml
fail_on:
  linting: error        # Fail on lint errors (ignore warnings)
  type_checking: error  # Fail on type errors
  security: high        # Fail on high/critical security issues
  testing: any          # Fail on any test failure
  coverage: below_threshold  # Fail if coverage < threshold
```

### CLI Override

Override thresholds from CLI:

```bash
# Fail on any security issue (for releases)
lucidscan scan --fail-on security:low

# Ignore linting in CI (still report)
lucidscan scan --fail-on linting:none
```

### Recommended Policies

| Environment | Linting | Type Checking | Security | Testing | Coverage |
|-------------|---------|---------------|----------|---------|----------|
| Development | warning | error | none | any | none |
| Pull Request | error | error | high | any | below_threshold |
| Main Branch | error | error | high | any | below_threshold |
| Release | error | error | medium | any | below_threshold |

---

## Configuration

### Project Configuration

Use `lucidscan.yml` for consistent configuration across local and CI:

```yaml
version: 1

pipeline:
  linting:
    enabled: true
    tools:
      - name: ruff
      - name: eslint

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
        args: ["-v", "--tb=short"]

  coverage:
    enabled: true
    threshold: 80

fail_on:
  linting: error
  type_checking: error
  security: high
  testing: any
  coverage: below_threshold

ignore:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/dist/**"
```

Then in CI, just run:

```bash
lucidscan scan --ci
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `LUCIDSCAN_CONFIG` | Path to config file |
| `LUCIDSCAN_CI` | Force CI mode (non-interactive) |
| `LUCIDSCAN_NO_COLOR` | Disable colored output |

---

## Caching

Cache the tool binaries and databases for faster CI runs.

### GitHub Actions

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.lucidscan
    key: lucidscan-${{ runner.os }}-${{ hashFiles('lucidscan.yml') }}
    restore-keys: |
      lucidscan-${{ runner.os }}-
```

### GitLab CI

```yaml
lucidscan:
  cache:
    key: lucidscan-$CI_RUNNER_EXECUTABLE_ARCH
    paths:
      - ~/.lucidscan/
  script:
    - pip install lucidscan
    - lucidscan scan --ci
```

### Bitbucket Pipelines

```yaml
definitions:
  caches:
    lucidscan: ~/.lucidscan

pipelines:
  default:
    - step:
        caches:
          - lucidscan
          - pip
        script:
          - pip install lucidscan
          - lucidscan scan --ci
```

---

## Docker Image

For faster CI without tool installation, use the Docker image:

```yaml
# GitHub Actions
jobs:
  quality:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/voldeq/lucidscan:latest
    steps:
      - uses: actions/checkout@v4
      - run: lucidscan scan --ci

# GitLab CI
lucidscan:
  image: ghcr.io/voldeq/lucidscan:latest
  script:
    - lucidscan scan --ci

# Bitbucket Pipelines
pipelines:
  default:
    - step:
        image: ghcr.io/voldeq/lucidscan:latest
        script:
          - lucidscan scan --ci
```

The Docker image includes:
- Pre-installed tool binaries (Ruff, Trivy, OpenGrep, Checkov, etc.)
- Pre-warmed vulnerability databases
- Ready for immediate scanning with no bootstrap time

### Available Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `X.Y.Z` | Specific version |

---

## Troubleshooting

### Tool Download Failures

If tools fail to download in CI:

1. Check network connectivity to GitHub/PyPI
2. Verify external URLs are not blocked by firewall
3. Use the Docker image (pre-downloaded tools)
4. Enable caching to avoid repeated downloads

### Timeout Issues

For large repositories:

```yaml
# GitHub Actions
- run: lucidscan scan --ci
  timeout-minutes: 30

# GitLab CI
lucidscan:
  timeout: 30 minutes
  script:
    - lucidscan scan --ci
```

### Debug Mode

Enable verbose output for troubleshooting:

```bash
lucidscan scan --ci --debug
```

### Permission Errors

The Docker image runs as root by default. For non-root:

```yaml
container:
  image: ghcr.io/voldeq/lucidscan:latest
  options: --user 1000:1000
```

### Test Discovery Issues

If tests aren't found:

```yaml
pipeline:
  testing:
    tools:
      - name: pytest
        args: ["tests/", "-v"]  # Explicit test directory
```

---

## Output Formats

### Table (Default)

Human-readable output for logs:

```bash
lucidscan scan --ci --format table
```

### JSON

Machine-readable for processing:

```bash
lucidscan scan --ci --format json --output results.json
```

### SARIF

For GitHub Code Scanning / VS Code:

```bash
lucidscan scan --ci --format sarif --output results.sarif
```

### Summary

Concise overview:

```bash
lucidscan scan --ci --format summary
```
