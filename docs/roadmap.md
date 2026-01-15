# LucidScan Roadmap

> **Vision**: The trust layer for AI-assisted development

LucidScan unifies code quality tools (linting, type checking, security, testing, coverage) into a single pipeline that auto-configures for any project and integrates with AI coding tools like Claude Code and Cursor.

---

## Roadmap Overview

```
    v0.1-v0.5              v0.6-v0.8               v0.9                  v1.0
        |                      |                    |                     |
   ─────●──────────────────────●────────────────────●─────────────────────●─────────
        |                      |                    |                     |
    COMPLETE              Language              CI/CD               Production
                          Expansion           Integration              Ready

  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │ Core        │      │ 5 Languages │      │ GitHub      │      │ Docs        │
  │ Security    │      │ 2 tools per │      │ Actions     │      │ Performance │
  │ MCP Server  │      │ domain      │      │ GitLab CI   │      │ Stability   │
  │ AI Tools    │      │ Go, C#      │      │ Pre-commit  │      │             │
  └─────────────┘      └─────────────┘      └─────────────┘      └─────────────┘
```

---

## Completed (v0.1 - v0.5)

All foundational work is complete. LucidScan is a fully functional code quality platform with AI integration.

### What's Built

| Component | Details |
|-----------|---------|
| **Core Framework** | CLI with subcommands, plugin system, pipeline orchestrator, configuration system |
| **Security Scanning** | Trivy (SCA, Container), OpenGrep (SAST), Checkov (IaC) |
| **Linting** | Ruff (Python), ESLint (JS/TS), Biome (JS/TS), Checkstyle (Java) |
| **Type Checking** | mypy (Python), pyright (Python), TypeScript (tsc) |
| **Testing** | pytest (Python), Jest (JS/TS), Karma (Angular), Playwright (E2E) |
| **Coverage** | coverage.py (Python), Istanbul (JS/TS) |
| **AI Integration** | MCP server, file watcher, structured AI instructions |
| **Output** | JSON, Table, SARIF, Summary reporters |

### Current Language Support

| Language | Linting | Type Checking | Testing | Coverage |
|----------|---------|---------------|---------|----------|
| Python | Ruff | mypy, pyright | pytest | coverage.py |
| JavaScript/TypeScript | ESLint, Biome | TypeScript | Jest | Istanbul |
| Java | Checkstyle | — | — | — |

### Commands Available Today

```bash
lucidscan init --claude-code         # Configure Claude Code
lucidscan init --cursor              # Configure Cursor
lucidscan autoconfigure              # Generate lucidscan.yml
lucidscan scan --all                 # Run complete pipeline
lucidscan scan --lint --fix          # Lint with auto-fix
lucidscan scan --type-check          # Type checking
lucidscan scan --test --coverage     # Tests with coverage
lucidscan serve --mcp                # MCP server for AI tools
lucidscan status                     # Show tool status
```

---

## v0.6 - v0.8 — Language Expansion

**Goal**: Support 5 popular languages with 2 tools per domain each

### Target Language Matrix

| Language | Linting | Type Checking | Testing | Coverage |
|----------|---------|---------------|---------|----------|
| **Python** | Ruff, Flake8 | mypy, pyright | pytest, unittest | coverage.py |
| **JS/TS** | ESLint, Biome | TypeScript (tsc) | Jest, Vitest | Istanbul, c8 |
| **Java** | Checkstyle, SpotBugs | (compiler) | JUnit, TestNG | JaCoCo, Cobertura |
| **Go** | golangci-lint, staticcheck | (compiler) | go test, testify | go cover |
| **C#** | StyleCop, Roslyn | (compiler) | xUnit, NUnit | Coverlet, dotCover |

### Implementation by Version

#### v0.6 — Complete Python & JS/TS

| Task | Status |
|------|--------|
| Flake8 linter plugin | Planned |
| unittest test runner plugin | Planned |
| Vitest test runner plugin | Planned |
| c8 coverage plugin | Planned |

#### v0.7 — Complete Java & Add Go

| Task | Status |
|------|--------|
| SpotBugs linter plugin | Planned |
| JUnit test runner plugin | Planned |
| TestNG test runner plugin | Planned |
| JaCoCo coverage plugin | Planned |
| Cobertura coverage plugin | Planned |
| Go language detection | Planned |
| golangci-lint plugin | Planned |
| staticcheck plugin | Planned |
| go test integration | Planned |
| go cover integration | Planned |

#### v0.8 — Add C#

| Task | Status |
|------|--------|
| C# language detection | Planned |
| StyleCop linter plugin | Planned |
| Roslyn analyzer plugin | Planned |
| xUnit test runner plugin | Planned |
| NUnit test runner plugin | Planned |
| Coverlet coverage plugin | Planned |
| dotCover coverage plugin | Planned |

### Security Domains (Unchanged)

Security scanning remains the same across all languages:
- **SCA**: Trivy (dependency vulnerabilities)
- **SAST**: OpenGrep (code patterns)
- **IaC**: Checkov (infrastructure as code)
- **Container**: Trivy (image scanning)

---

## v0.9 — CI Integration

**Goal**: Native CI/CD pipeline support for automated quality gates

### Key Deliverables

| Feature | Description |
|---------|-------------|
| **GitHub Actions** | Generate `.github/workflows/lucidscan.yml` |
| **GitLab CI** | Generate `.gitlab-ci.yml` with LucidScan job |
| **Pre-commit hooks** | Integration with pre-commit framework |
| **SARIF upload** | Automatic upload to GitHub Security tab |
| **CI output mode** | Optimized output for CI environments |
| **Exit codes** | Clear pass/fail for pipeline gating |

### User Experience

```bash
# Generate CI configuration
lucidscan init --github-actions      # Create GitHub workflow
lucidscan init --gitlab-ci           # Create GitLab CI config
lucidscan init --pre-commit          # Add to .pre-commit-config.yaml

# CI-optimized scanning
lucidscan scan --all --ci            # CI mode with proper exit codes
lucidscan scan --all --sarif-upload  # Upload results to GitHub
```

### Generated GitHub Actions Workflow

```yaml
# .github/workflows/lucidscan.yml
name: LucidScan
on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install LucidScan
        run: pip install lucidscan
      - name: Run quality checks
        run: lucidscan scan --all --format sarif --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## v1.0 — Production Ready

**Goal**: Polish, stability, and comprehensive documentation

### Key Deliverables

| Feature | Description |
|---------|-------------|
| **Documentation** | Complete user guide, API reference, plugin development guide |
| **Performance** | Incremental checking, result caching, parallel execution |
| **Stability** | Error handling, graceful degradation, clear error messages |
| **Distribution** | PyPI, Docker image, Homebrew formula |

### Success Criteria

- [ ] Complete documentation with examples
- [ ] Performance optimized for large codebases (10k+ files)
- [ ] Stable API (no breaking changes in 1.x)
- [ ] Production use validated by early adopters

---

## Future Considerations

Beyond v1.0, potential directions include:

| Direction | Description |
|-----------|-------------|
| **More languages** | Rust, PHP, Kotlin, Swift |
| **VS Code extension** | Native IDE integration beyond MCP |
| **Team features** | Shared configs, policy enforcement, dashboards |
| **Custom rules** | User-defined linting and security rules |
| **Cloud service** | Optional SaaS for team management |

These are not committed — they depend on user feedback and adoption.

---

## Changelog

| Version | Status | Highlights |
|---------|--------|------------|
| v0.1-v0.5 | Complete | Core framework, security scanning, linting, type checking, testing, coverage, MCP server, AI integration |
| v0.6 | Planned | Complete Python (Flake8, unittest) and JS/TS (Vitest, c8) tool coverage |
| v0.7 | Planned | Complete Java (SpotBugs, JUnit, TestNG, JaCoCo, Cobertura) and add Go support |
| v0.8 | Planned | Add C# support (StyleCop, Roslyn, xUnit, NUnit, Coverlet, dotCover) |
| v0.9 | Planned | CI integration (GitHub Actions, GitLab CI, pre-commit) |
| v1.0 | Planned | Production ready (docs, performance, stability) |

---

## Contributing

See the [full specification](main.md) for detailed technical requirements.

To contribute:
1. Pick an item from the current milestone
2. Open an issue to discuss approach
3. Submit a PR

We welcome contributions for:
- New tool plugins (especially Go and C#)
- CI integration templates
- Documentation improvements
- Bug fixes and testing
