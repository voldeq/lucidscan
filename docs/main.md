# LucidScan

## 1. Problem Statement

AI coding assistants have fundamentally changed software development. Tools like Claude Code, Cursor, GitHub Copilot, and Windsurf can generate hundreds of lines of code in seconds. But this speed creates a new problem: **developers cannot trust AI-generated code**.

The trust gap manifests in several ways:

- **Security vulnerabilities**: AI can introduce injection flaws, hardcoded secrets, insecure configurations
- **Code quality issues**: Linting errors, type mismatches, inconsistent patterns
- **Test gaps**: AI-generated code often lacks test coverage
- **Best practice violations**: AI doesn't know your team's conventions

Developers currently address this through manual review and fragmented tooling:

- Run ESLint, then Ruff, then mypy separately
- Run security scanners (Trivy, Semgrep) as an afterthought
- Copy-paste error messages back to the AI for fixes
- Repeat until the code passes all checks

This workflow is **slow, manual, and error-prone**. The feedback loop between AI agents and deterministic quality tools is broken.

### 1.1 The Missing Layer

What developers need is a **trust layer** that:

1. **Auto-configures** quality tools for any codebase with a single command
2. **Unifies** linting, security, testing, and coverage in one pipeline
3. **Integrates with CI** so the same checks run locally and in pipelines
4. **Feeds back to AI agents** in real-time, instructing them to fix issues automatically

This trust layer doesn't replace existing tools — it orchestrates them and bridges the gap between deterministic analysis and AI-assisted development.

### 1.2 Vision: Guardrails for AI Coding

LucidScan is the **trust layer for AI-assisted development**. It provides:

```
lucidscan init --all
→ Configures AI tools (Claude Code, Cursor)

"Autoconfigure LucidScan" (via AI)
→ AI analyzes your codebase
→ Asks you targeted questions
→ Generates lucidscan.yml configuration
→ Sets up pre-commit hooks (optional)

AI writes code → LucidScan checks → AI fixes → repeat
```

The core insight: **deterministic tools catch mistakes reliably, but the feedback loop to AI agents is broken**. LucidScan bridges this gap by letting your AI assistant configure and run quality checks.

| Traditional Workflow | LucidScan Workflow |
|---------------------|-------------------|
| AI writes code | AI writes code |
| Human runs linters manually | LucidScan runs automatically |
| Human reads error output | LucidScan formats instructions |
| Human tells AI what to fix | LucidScan tells AI what to fix |
| AI fixes, human re-runs | AI fixes, LucidScan re-checks |
| Repeat 5-10 times | Automated loop |

---

## 2. Goals

LucidScan is a **unified code quality pipeline** with native AI agent integration. It achieves:

### 2.1 Zero-Config Initialization

```bash
# 1. Set up AI tools
lucidscan init --all

# 2. Ask your AI: "Autoconfigure LucidScan for this project"
```

The AI-assisted setup:
- Detects languages, frameworks, and existing tools in your codebase
- Asks targeted questions about coverage thresholds and strictness
- Generates a complete `lucidscan.yml` configuration
- Optionally creates pre-commit hooks

Alternative CLI approach:
```bash
lucidscan autoconfigure              # Interactive
lucidscan autoconfigure --ci github  # With CI config
```

### 2.2 Unified Pipeline

A single configuration file controls:

| Domain | Tools | What It Catches |
|--------|-------|-----------------|
| **Linting** | Ruff, ESLint, Biome | Style, formatting, code smells |
| **Type Checking** | mypy, TypeScript, Pyright | Type errors |
| **Security** | Trivy, OpenGrep, Checkov | Vulnerabilities, misconfigurations |
| **Testing** | pytest, Jest, Go test | Test failures |
| **Coverage** | coverage.py, Istanbul, Go cover | Coverage gaps |

All results normalized to a common schema. One exit code for CI gates.

### 2.3 AI Agent Integration

LucidScan bridges deterministic tools and AI agents:

```yaml
# lucidscan.yml
ai_integration:
  claude_code: true
  cursor: true
  mode: realtime  # or: on_save, on_commit
```

When enabled:
- LucidScan runs as an MCP server or hooks into AI tool configurations
- Issues are formatted as structured instructions for the AI
- The AI receives: "Fix issue X in file Y by doing Z"
- Automatic feedback loop until code passes

### 2.4 CI Integration

```bash
lucidscan autoconfigure --ci github
```

Generates ready-to-use CI configuration:
- GitHub Actions workflow
- GitLab CI template
- Bitbucket Pipelines configuration

Same checks run locally and in CI. No configuration drift.

---

## 3. Non-Goals

LucidScan focuses on orchestration and integration, not reimplementing tools:

### 3.1 Not a Scanner/Linter

LucidScan does **not** implement:
- Custom linting rules (uses ESLint, Ruff, etc.)
- Custom security scanning (uses Trivy, OpenGrep, etc.)
- Custom test runners (uses pytest, Jest, etc.)

It orchestrates existing best-in-class tools.

### 3.2 Not a Dashboard

LucidScan is **CLI-first**:
- No web dashboard
- No hosted service
- No accounts or authentication

Results are local. CI integration uses standard mechanisms (exit codes, SARIF).

### 3.3 Not AI-Driven

AI does **not** make decisions:
- AI cannot suppress findings
- AI cannot change severity levels
- AI cannot skip checks

LucidScan uses AI to **explain and fix** issues, not to decide what matters.

### 3.4 Not a Replacement for CI

LucidScan generates CI configuration but does **not** replace CI systems:
- GitHub Actions, GitLab CI, Bitbucket Pipelines remain the execution environment
- LucidScan is a command that runs within those systems

---

## 4. Target Users

### 4.1 Primary: Developers Using AI Coding Tools

Developers who:
- Use Claude Code, Cursor, Copilot, or similar AI assistants
- Want confidence that AI-generated code is production-ready
- Need fast feedback loops without manual tool orchestration
- Work in teams with shared quality standards

**Key motivation**: "I want to trust AI-generated code without manually running 5 different tools."

### 4.2 Secondary: DevOps Engineers

Engineers who:
- Set up CI/CD pipelines for teams
- Want consistent quality gates across projects
- Need to onboard new projects quickly
- Manage tool versions and configurations

**Key motivation**: "I want to set up comprehensive quality checks in 5 minutes, not 5 hours."

### 4.3 Teams Adopting AI Coding

Teams that:
- Are increasing AI tool usage but worry about code quality
- Want guardrails before AI code reaches main branches
- Need visibility into what AI is introducing

**Key motivation**: "We want AI velocity with human-level quality."

---

## 5. Core Product Requirements

### 5.1 The `autoconfigure` Command

The `lucidscan autoconfigure` command is the primary entry point for project setup. It MUST:

#### 5.1.1 Codebase Detection

Automatically detect:
- **Languages**: Python, JavaScript/TypeScript, Go, Rust, Java, etc.
- **Package managers**: npm, pip, cargo, go.mod, etc.
- **Frameworks**: React, Django, FastAPI, Express, etc.
- **Existing tools**: .eslintrc, pyproject.toml, ruff.toml, etc.
- **CI systems**: .github/workflows, .gitlab-ci.yml, bitbucket-pipelines.yml

Detection MUST be fast (<5 seconds for typical repos).

#### 5.1.2 Interactive Configuration

Ask targeted questions based on detection:

```
Detected: Python 3.11, FastAPI, pytest

? Linter: [Ruff (recommended)] / Flake8 / Skip
? Type checker: [mypy (recommended)] / Pyright / Skip
? Security scanner: [Trivy + OpenGrep (recommended)] / Trivy only / Skip
? Test runner: [pytest (detected)] / Skip
? Coverage threshold: [80%] / Custom / Skip
? CI platform: [GitHub Actions (detected)] / GitLab / Bitbucket / Skip
```

Questions MUST:
- Respect existing configuration (don't ask about tools already configured)
- Provide sensible defaults
- Allow skipping any category
- Complete in <2 minutes for typical setups

#### 5.1.3 Configuration Generation

Generate `lucidscan.yml` with all settings:

```yaml
# Generated by lucidscan autoconfigure
version: 1

project:
  name: my-fastapi-app
  languages: [python]

pipeline:
  linting:
    enabled: true
    tools:
      - name: ruff
        config: pyproject.toml

  type_checking:
    enabled: true
    tools:
      - name: mypy
        strict: true

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
        args: ["-v"]

  coverage:
    enabled: true
    threshold: 80
    tool: coverage.py

fail_on:
  linting: error
  type_checking: error
  security: high
  testing: any
  coverage: below_threshold

ignore:
  - "**/__pycache__/**"
  - "**/node_modules/**"
  - "**/.venv/**"
```

#### 5.1.4 CI Configuration

When a CI platform is detected or selected, generate/update CI configuration:

**GitHub Actions** (`.github/workflows/lucidscan.yml`):
```yaml
name: LucidScan

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install lucidscan
      - run: lucidscan scan --ci
```

**GitLab CI** (merge into `.gitlab-ci.yml`):
```yaml
lucidscan:
  image: python:3.11
  script:
    - pip install lucidscan
    - lucidscan scan --ci
```

**Bitbucket Pipelines** (merge into `bitbucket-pipelines.yml`):
```yaml
pipelines:
  default:
    - step:
        name: LucidScan
        script:
          - pip install lucidscan
          - lucidscan scan --ci
```

### 5.2 The `scan` Command

```bash
lucidscan scan [--ci] [--fix] [--format FORMAT]
```

#### 5.2.1 Pipeline Execution

Execute the configured pipeline in order:

1. **Linting** → Run configured linters
2. **Type Checking** → Run type checkers
3. **Security** → Run security scanners
4. **Testing** → Run test suites
5. **Coverage** → Check coverage thresholds

Each stage produces normalized results. Stages can run in parallel where independent.

#### 5.2.2 Unified Output

All results normalized to common schema:

```json
{
  "issues": [
    {
      "id": "ruff-E501",
      "domain": "linting",
      "tool": "ruff",
      "severity": "warning",
      "file": "src/main.py",
      "line": 42,
      "column": 89,
      "message": "Line too long (120 > 88)",
      "rule": "E501",
      "fixable": true,
      "fix": {
        "description": "Split line or increase line length limit"
      }
    }
  ],
  "summary": {
    "linting": { "errors": 0, "warnings": 3 },
    "type_checking": { "errors": 1, "warnings": 0 },
    "security": { "critical": 0, "high": 1, "medium": 2 },
    "testing": { "passed": 42, "failed": 0 },
    "coverage": { "percentage": 85, "threshold": 80, "passed": true }
  },
  "passed": false,
  "exit_code": 1
}
```

#### 5.2.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Issues found above threshold |
| 2 | Tool execution error |
| 3 | Configuration error |

#### 5.2.4 Auto-Fix Mode

```bash
lucidscan scan --fix
```

When `--fix` is enabled:
- Run fixable linters in fix mode (ruff --fix, eslint --fix)
- Report what was fixed
- Re-run checks to verify fixes

### 5.3 The `serve` Command (AI Integration)

```bash
lucidscan serve [--mcp] [--port PORT]
```

#### 5.3.1 MCP Server Mode

Run as an MCP (Model Context Protocol) server that AI tools can connect to:

```bash
lucidscan serve --mcp
```

The MCP server provides:
- `scan` tool: Run full pipeline or specific domains
- `check_file` tool: Check a specific file
- `get_issues` tool: Get current issues
- `explain_issue` tool: Get AI-friendly explanation of an issue

#### 5.3.2 File Watcher Mode

```bash
lucidscan serve --watch
```

Watch for file changes and run relevant checks:
- On Python file change → Run Ruff, mypy for that file
- On JS/TS file change → Run ESLint, TypeScript for that file
- Debounce rapid changes

#### 5.3.3 AI Instruction Format

When serving AI agents, issues are formatted as actionable instructions:

```json
{
  "instruction": "Fix security vulnerability in src/api/auth.py",
  "issue": {
    "type": "security",
    "severity": "high",
    "rule": "opengrep.python.security.hardcoded-password"
  },
  "location": {
    "file": "src/api/auth.py",
    "line": 23,
    "code_snippet": "password = \"admin123\""
  },
  "fix_guidance": {
    "description": "Hardcoded password detected. Move to environment variable.",
    "suggested_fix": "password = os.environ.get('DB_PASSWORD')",
    "steps": [
      "Import os module if not already imported",
      "Replace hardcoded password with os.environ.get('DB_PASSWORD')",
      "Add DB_PASSWORD to .env.example with placeholder value",
      "Document the required environment variable"
    ]
  }
}
```

### 5.4 Configuration

#### 5.4.1 Configuration File

`lucidscan.yml` in project root:

```yaml
version: 1

project:
  name: string
  languages: [string]

pipeline:
  linting:
    enabled: boolean
    tools:
      - name: string
        config: string  # Path to tool config
        args: [string]  # Additional arguments

  type_checking:
    enabled: boolean
    tools:
      - name: string
        strict: boolean
        args: [string]

  security:
    enabled: boolean
    tools:
      - name: string
        domains: [sca, sast, iac, container, secrets]
        severity_threshold: string

  testing:
    enabled: boolean
    tools:
      - name: string
        args: [string]
        coverage: boolean

  coverage:
    enabled: boolean
    threshold: number
    tool: string

fail_on:
  linting: error | warning | none
  type_checking: error | warning | none
  security: critical | high | medium | low | none
  testing: any | none
  coverage: below_threshold | none

ignore:
  - string  # Glob patterns

ai_integration:
  claude_code: boolean
  cursor: boolean
  mode: realtime | on_save | on_commit
```

#### 5.4.2 Ignore File

`.lucidscanignore` supports gitignore syntax:

```
# Dependencies
node_modules/
.venv/
vendor/

# Build artifacts
dist/
build/
*.pyc

# Generated files
*.generated.ts
```

#### 5.4.3 Inline Ignores

Support tool-native inline ignores:
- Ruff: `# noqa: E501`
- ESLint: `// eslint-disable-next-line`
- OpenGrep: `# nosemgrep`
- Checkov: `# checkov:skip=CKV_AWS_1`

### 5.5 Tool Management

#### 5.5.1 Automatic Installation

Tools are installed automatically when needed:

```bash
$ lucidscan scan
Installing ruff 0.8.0... done
Installing trivy 0.58.0... done
Running pipeline...
```

Installation uses:
- pip for Python tools (ruff, mypy, coverage)
- npm for JS tools (eslint, typescript) — only if package.json exists
- Direct binary download for standalone tools (trivy, opengrep)

#### 5.5.2 Version Pinning

Tools are pinned to specific versions for reproducibility:

```yaml
# lucidscan.yml
tools:
  ruff: "0.8.0"
  trivy: "0.58.0"
  opengrep: "1.12.0"
```

#### 5.5.3 Binary Cache

Binaries cached at `~/.lucidscan/`:

```
~/.lucidscan/
├── bin/
│   ├── trivy/0.58.0/trivy
│   ├── opengrep/1.12.0/opengrep
│   └── checkov/3.2.0/checkov
├── cache/
│   └── trivy/db/  # Vulnerability database
└── config.yml     # Global settings
```

---

## 6. System Architecture

### 6.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LucidScan CLI                            │
├─────────────────────────────────────────────────────────────────┤
│  Commands                                                       │
│  ├── init      → Codebase detection, config generation          │
│  ├── scan      → Pipeline execution                             │
│  ├── serve     → MCP server / file watcher                      │
│  └── status    → Show configuration and tool versions           │
├─────────────────────────────────────────────────────────────────┤
│  Pipeline Orchestrator                                          │
│  ├── Stage execution (lint → typecheck → security → test)       │
│  ├── Parallel execution where possible                          │
│  ├── Result aggregation                                         │
│  └── Threshold evaluation                                       │
├─────────────────────────────────────────────────────────────────┤
│  Tool Plugins                                                   │
│  ├── Linting:     RuffPlugin, ESLintPlugin, BiomePlugin         │
│  ├── TypeCheck:   MypyPlugin, TypeScriptPlugin, PyrightPlugin   │
│  ├── Security:    TrivyPlugin, OpenGrepPlugin, CheckovPlugin    │
│  ├── Testing:     PytestPlugin, JestPlugin, GoTestPlugin        │
│  └── Coverage:    CoveragePlugin, IstanbulPlugin, GoCoverPlugin │
├─────────────────────────────────────────────────────────────────┤
│  Output Layer                                                   │
│  ├── Reporters:   JSON, Table, SARIF, Summary                   │
│  ├── AI Format:   Structured instructions for AI agents         │
│  └── CI Format:   Annotations, exit codes                       │
├─────────────────────────────────────────────────────────────────┤
│  AI Integration Layer                                           │
│  ├── MCP Server:  Tools for AI agents to invoke                 │
│  ├── File Watcher: Real-time checking                           │
│  └── Instruction Formatter: Issue → actionable fix guidance     │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Plugin Interface

All tool plugins implement a common interface:

```python
class ToolPlugin(ABC):
    """Base class for all tool plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin identifier (e.g., 'ruff', 'trivy')."""

    @property
    @abstractmethod
    def domain(self) -> ToolDomain:
        """Domain: LINTING, TYPE_CHECKING, SECURITY, TESTING, COVERAGE."""

    @property
    @abstractmethod
    def languages(self) -> list[str]:
        """Languages this plugin supports."""

    @abstractmethod
    def detect(self, context: ProjectContext) -> bool:
        """Return True if this plugin is applicable to the project."""

    @abstractmethod
    def ensure_installed(self) -> Path:
        """Ensure the tool is installed, return path to binary."""

    @abstractmethod
    def run(self, context: ScanContext) -> list[Issue]:
        """Execute the tool and return normalized issues."""

    def fix(self, context: ScanContext) -> FixResult:
        """Run in fix mode if supported. Default: not supported."""
        raise NotImplementedError("This tool does not support auto-fix")
```

### 6.3 Codebase Detector

The codebase detector identifies project characteristics:

```python
@dataclass
class ProjectContext:
    root: Path
    languages: list[str]           # ["python", "typescript"]
    package_managers: list[str]    # ["pip", "npm"]
    frameworks: list[str]          # ["fastapi", "react"]
    existing_tools: dict[str, Path]  # {"ruff": "pyproject.toml"}
    ci_systems: list[str]          # ["github_actions"]
    git_root: Path | None
```

Detection strategy:
1. Scan for marker files (package.json, pyproject.toml, go.mod, etc.)
2. Parse lockfiles to identify dependencies
3. Check for existing tool configurations
4. Identify CI configuration files

### 6.4 MCP Server

The MCP server exposes tools for AI agents:

```python
class LucidScanMCPServer:
    """MCP server for AI agent integration."""

    @tool
    def scan(
        self,
        domains: list[str] = ["all"],
        files: list[str] | None = None
    ) -> ScanResult:
        """Run quality checks on the codebase or specific files."""

    @tool
    def check_file(self, file_path: str) -> list[Issue]:
        """Check a specific file and return issues."""

    @tool
    def get_fix_instructions(self, issue_id: str) -> FixInstruction:
        """Get detailed fix instructions for a specific issue."""

    @tool
    def apply_fix(self, issue_id: str) -> FixResult:
        """Apply auto-fix for a fixable issue."""
```

### 6.5 Unified Issue Schema

All tools normalize to this schema:

```python
@dataclass
class Issue:
    id: str                    # Unique identifier
    domain: ToolDomain         # LINTING, SECURITY, etc.
    tool: str                  # "ruff", "trivy", etc.
    severity: Severity         # CRITICAL, HIGH, MEDIUM, LOW, WARNING, INFO

    # Location
    file: str
    line: int
    column: int | None
    end_line: int | None
    end_column: int | None

    # Content
    rule: str                  # Rule ID (e.g., "E501", "CVE-2024-1234")
    message: str               # Human-readable message
    code_snippet: str | None   # Relevant code

    # Fix information
    fixable: bool
    fix_description: str | None
    suggested_fix: str | None

    # Metadata
    documentation_url: str | None
    extra: dict[str, Any]      # Tool-specific data
```

---

## 7. AI Integration Specification

### 7.1 Integration Modes

LucidScan supports multiple integration modes with AI coding tools:

#### 7.1.1 MCP Server Mode (Recommended)

LucidScan runs as an MCP server that AI tools connect to:

```bash
lucidscan serve --mcp
```

**For Claude Code** (`~/.claude/mcp_servers.json`):
```json
{
  "lucidscan": {
    "command": "lucidscan",
    "args": ["serve", "--mcp"],
    "cwd": "/path/to/project"
  }
}
```

**For Cursor** (MCP configuration):
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

#### 7.1.2 Hooks Mode

LucidScan can run via editor hooks:

**Claude Code hooks** (`~/.claude/settings.json`):
```json
{
  "hooks": {
    "post_tool_call": [
      {
        "match": { "tool": "write", "edit": "*" },
        "command": "lucidscan scan --files $CHANGED_FILES --format ai"
      }
    ]
  }
}
```

#### 7.1.3 File Watcher Mode

For editors without MCP/hooks support:

```bash
lucidscan serve --watch --output /tmp/lucidscan-issues.json
```

Editor plugins can read the output file and display issues.

### 7.2 AI Instruction Format

When providing feedback to AI agents, issues are formatted for actionability:

```json
{
  "total_issues": 3,
  "blocking": true,
  "instructions": [
    {
      "priority": 1,
      "action": "FIX_SECURITY_VULNERABILITY",
      "summary": "Hardcoded password in auth.py:23",
      "details": {
        "issue_type": "security",
        "severity": "high",
        "rule": "opengrep.python.security.hardcoded-password",
        "file": "src/api/auth.py",
        "line": 23,
        "current_code": "password = \"admin123\"",
        "problem": "Hardcoded passwords are a security risk. They can be extracted from source code and version history.",
        "fix_steps": [
          "Add 'import os' at the top of the file if not present",
          "Replace the hardcoded password with: password = os.environ.get('DB_PASSWORD')",
          "Ensure DB_PASSWORD is set in your environment or .env file"
        ],
        "fixed_code": "password = os.environ.get('DB_PASSWORD')"
      }
    },
    {
      "priority": 2,
      "action": "FIX_TYPE_ERROR",
      "summary": "Type mismatch in utils.py:45",
      "details": {
        "issue_type": "type_checking",
        "severity": "error",
        "rule": "mypy.arg-type",
        "file": "src/utils.py",
        "line": 45,
        "current_code": "process_items(items: str)",
        "problem": "Argument 'items' has type 'str' but expected 'list[str]'",
        "fix_steps": [
          "Change the function call to pass a list instead of a string",
          "Or update the function signature if it should accept a string"
        ]
      }
    }
  ]
}
```

### 7.3 Feedback Loop

The AI integration creates an automated feedback loop:

```
1. AI writes/modifies code
2. LucidScan automatically runs relevant checks
3. Issues are formatted as instructions
4. AI receives instructions and applies fixes
5. LucidScan re-checks
6. Repeat until clean (or max iterations reached)
```

Configuration:
```yaml
ai_integration:
  max_fix_iterations: 3
  auto_fix_domains: [linting, type_checking]  # Security requires human review
  require_human_approval: [security]
```

---

## 8. CLI Specification

### 8.1 Global Options

```
lucidscan [OPTIONS] COMMAND [ARGS]

Global Options:
  --config, -c PATH    Configuration file (default: lucidscan.yml)
  --verbose, -v        Verbose output
  --quiet, -q          Minimal output
  --debug              Debug mode with full traces
  --version            Show version
  --help, -h           Show help
```

### 8.2 Commands

#### 8.2.1 `init`

```
lucidscan init [OPTIONS]

Configure AI tools (Claude Code, Cursor) to use LucidScan.

Options:
  --claude-code        Configure Claude Code MCP settings
  --cursor             Configure Cursor MCP settings
  --all                Configure all supported AI tools
  --dry-run            Show changes without applying
  --force              Overwrite existing configuration
  --remove             Remove LucidScan from tool configuration

Examples:
  lucidscan init --claude-code      # Configure Claude Code
  lucidscan init --cursor           # Configure Cursor
  lucidscan init --all              # Configure all AI tools
```

#### 8.2.2 `autoconfigure`

```
lucidscan autoconfigure [OPTIONS]

Auto-configure LucidScan for the current project (detect languages, generate lucidscan.yml).

Options:
  --ci PLATFORM        Generate CI config (github, gitlab, bitbucket)
  --non-interactive    Use defaults without prompting
  --force              Overwrite existing configuration

Examples:
  lucidscan autoconfigure                    # Interactive setup
  lucidscan autoconfigure --ci github        # With GitHub Actions
  lucidscan autoconfigure --non-interactive  # Use all defaults
```

#### 8.2.3 `scan`

```
lucidscan scan [OPTIONS] [PATHS...]

Run the quality pipeline.

Options:
  --domain, -d DOMAIN  Run specific domain (linting, security, testing, etc.)
  --fix                Apply auto-fixes where possible
  --ci                 CI mode (non-interactive, annotations)
  --format FORMAT      Output format (table, json, sarif, ai)
  --fail-on LEVEL      Override fail threshold
  --files FILE...      Check specific files only

Examples:
  lucidscan scan                    # Run full pipeline
  lucidscan scan --domain security  # Security only
  lucidscan scan --fix              # Auto-fix what's possible
  lucidscan scan --format json      # JSON output
  lucidscan scan src/               # Scan specific directory
```

#### 8.2.4 `serve`

```
lucidscan serve [OPTIONS]

Run LucidScan as a server for AI integration.

Options:
  --mcp                Run as MCP server
  --watch              Watch files for changes
  --port PORT          HTTP port for status endpoint (default: 7432)

Examples:
  lucidscan serve --mcp             # MCP server for Claude Code/Cursor
  lucidscan serve --watch           # File watcher mode
```

#### 8.2.5 `status`

```
lucidscan status [OPTIONS]

Show current configuration and tool status.

Options:
  --tools              Show installed tool versions
  --config             Show effective configuration

Examples:
  lucidscan status                  # Overview
  lucidscan status --tools          # Tool versions
```

### 8.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no issues above threshold |
| 1 | Issues found above threshold |
| 2 | Tool execution error |
| 3 | Configuration error |
| 4 | Installation/bootstrap error |

---

## 9. Supported Tools

### 9.1 Linting

| Tool | Languages | Install Method |
|------|-----------|----------------|
| Ruff | Python | pip |
| ESLint | JavaScript, TypeScript | npm |
| Biome | JavaScript, TypeScript, JSON | npm / binary |
| golangci-lint | Go | binary |
| Clippy | Rust | rustup |

### 9.2 Type Checking

| Tool | Languages | Install Method |
|------|-----------|----------------|
| mypy | Python | pip |
| Pyright | Python | pip / npm |
| TypeScript | TypeScript | npm |
| Go vet | Go | bundled |

### 9.3 Security

| Tool | Domains | Install Method |
|------|---------|----------------|
| Trivy | SCA, Container, IaC | binary |
| OpenGrep | SAST | binary |
| Checkov | IaC | pip / binary |
| Gitleaks | Secrets | binary |

### 9.4 Testing

| Tool | Languages | Install Method |
|------|-----------|----------------|
| pytest | Python | pip |
| Jest | JavaScript, TypeScript | npm |
| Go test | Go | bundled |
| Cargo test | Rust | bundled |

### 9.5 Coverage

| Tool | Languages | Install Method |
|------|-----------|----------------|
| coverage.py | Python | pip |
| Istanbul/nyc | JavaScript, TypeScript | npm |
| Go cover | Go | bundled |
| Tarpaulin | Rust | cargo |

---

## 10. CI Integration

### 10.1 GitHub Actions

Generated workflow (`.github/workflows/lucidscan.yml`):

```yaml
name: LucidScan

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

      - name: Run LucidScan
        run: lucidscan scan --ci --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### 10.2 GitLab CI

Generated template (merged into `.gitlab-ci.yml`):

```yaml
lucidscan:
  stage: test
  image: python:3.11
  script:
    - pip install lucidscan
    - lucidscan scan --ci
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### 10.3 Bitbucket Pipelines

Generated template (merged into `bitbucket-pipelines.yml`):

```yaml
definitions:
  steps:
    - step: &lucidscan
        name: LucidScan
        image: python:3.11
        script:
          - pip install lucidscan
          - lucidscan scan --ci

pipelines:
  default:
    - step: *lucidscan
  pull-requests:
    '**':
      - step: *lucidscan
```

---

## 11. Development Phases

### Phase 1: Foundation

**Goal**: Core pipeline with `init` and `scan` commands

- [ ] Codebase detector (languages, frameworks, existing tools)
- [ ] Configuration generator (`lucidscan init`)
- [ ] Pipeline orchestrator
- [ ] Initial tool plugins:
  - [ ] Ruff (Python linting)
  - [ ] ESLint (JS/TS linting)
  - [ ] mypy (Python type checking)
  - [ ] Trivy (SCA, container security)
  - [ ] OpenGrep (SAST)
  - [ ] pytest (Python testing)
- [ ] Reporters: Table, JSON, SARIF
- [ ] CI config generation (GitHub Actions)

**Milestone**: `lucidscan init && lucidscan scan` works end-to-end

### Phase 2: Expanded Coverage

**Goal**: More tools and CI platforms

- [ ] Additional tool plugins:
  - [ ] Biome (JS/TS)
  - [ ] Checkov (IaC)
  - [ ] golangci-lint (Go)
  - [ ] Jest (JS/TS testing)
  - [ ] coverage.py (Python coverage)
- [ ] CI platforms:
  - [ ] GitLab CI
  - [ ] Bitbucket Pipelines
- [ ] Auto-fix mode (`--fix`)

**Milestone**: Support for Python, JavaScript/TypeScript, Go projects

### Phase 3: AI Integration

**Goal**: MCP server and AI feedback loop

- [ ] MCP server implementation (`lucidscan serve --mcp`)
- [ ] AI instruction formatter
- [ ] File watcher mode
- [ ] Claude Code integration guide
- [ ] Cursor integration guide
- [ ] Feedback loop configuration

**Milestone**: AI agents can invoke LucidScan and receive fix instructions

### Phase 4: Polish

**Goal**: Production readiness

- [ ] Comprehensive documentation
- [ ] Plugin SDK for third-party tools
- [ ] Performance optimization (caching, incremental checks)
- [ ] Telemetry (opt-in, anonymized)
- [ ] Error handling hardening

**Milestone**: v1.0 release

---

## 12. Appendix

### A. Glossary

| Term | Definition |
|------|------------|
| **Domain** | Category of checks: linting, type checking, security, testing, coverage |
| **Tool** | Underlying program (Ruff, Trivy, pytest) |
| **Plugin** | LucidScan adapter for a tool |
| **Pipeline** | Sequence of domains to execute |
| **Issue** | Single finding from any tool |
| **MCP** | Model Context Protocol, standard for AI tool integration |

### B. Configuration Schema

Full JSON Schema for `lucidscan.yml` available at:
`https://lucidscan.dev/schema/v1.json`

### C. Environment Variables

| Variable | Purpose |
|----------|---------|
| `LUCIDSCAN_CONFIG` | Path to config file |
| `LUCIDSCAN_CACHE_DIR` | Cache directory (default: `~/.lucidscan`) |
| `LUCIDSCAN_NO_COLOR` | Disable colored output |
| `LUCIDSCAN_CI` | Force CI mode |
