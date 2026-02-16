# Getting Started with LucidShark for TypeScript Projects

This guide walks you through setting up LucidShark on a TypeScript project, from installation to your first scan.

## Prerequisites

- **Node.js 18+** and **npm** (or yarn/pnpm)
- **Python 3.10+** or use the standalone binary (no Python required)
- A TypeScript project with a `package.json` and `tsconfig.json`

## Install LucidShark

Option A -- pip (requires Python 3.10+):

```bash
pip install lucidshark
```

Option B -- standalone binary (no Python required):

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/lucidshark-code/lucidshark/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/lucidshark-code/lucidshark/main/install.ps1 | iex
```

Verify the installation:

```bash
lucidshark --version
# lucidshark 0.5.25
```

## Auto-Configure Your Project

Run autoconfigure from your project root:

```bash
lucidshark autoconfigure
```

Example output for a React + TypeScript project:

```
Analyzing project...

Detected:
  Languages:    Typescript, Javascript
  Frameworks:   React
  Testing:      jest
  Tools:        eslint, typescript

Configuration:
  Linter:       eslint (detected)
  Type checker: typescript (detected)
  Security:     trivy, opengrep
  Test runner:  jest (detected)
  Duplication:  duplo (threshold: 10%)

? Proceed with this configuration? Yes

Generating configuration...
  Created lucidshark.yml

Done! Next steps:
  1. Review the generated lucidshark.yml
  2. Run 'lucidshark scan --all' to test the configuration
```

Use `-y` to skip prompts: `lucidshark autoconfigure -y`

### ESLint vs Biome

LucidShark supports both ESLint and Biome for linting. Autoconfigure picks whichever is already in your project. If neither is detected, it defaults to ESLint.

To use Biome instead, edit your `lucidshark.yml`:

```yaml
pipeline:
  linting:
    tools:
      - name: biome   # instead of eslint
```

## Review the Generated Config

Open `lucidshark.yml`. For a typical TypeScript project:

```yaml
version: 1

project:
  name: my-react-app
  languages: [typescript, javascript]

pipeline:
  linting:
    enabled: true
    tools:
      - name: eslint

  type_checking:
    enabled: true
    tools:
      - name: typescript

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
      - name: jest

  coverage:
    enabled: true
    tools:
      - name: istanbul
    threshold: 80

fail_on:
  linting: error
  type_checking: error
  security: high
  testing: any
  coverage: below_threshold

ignore:
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/coverage/**"
```

Key sections:
- **pipeline** -- Which tools to run. Each domain can be toggled independently.
- **fail_on** -- When LucidShark returns a non-zero exit code.
- **ignore** -- Glob patterns for files to skip (gitignore-style syntax).

You can skip the config file entirely and use a preset:

```bash
lucidshark scan --preset typescript-strict
```

### tsconfig.json Interaction

LucidShark runs `tsc` for type checking, which uses your existing `tsconfig.json`. LucidShark does not modify or override your TypeScript configuration. Note that `tsc` always checks the full project -- it does not support per-file scanning.

## Run Your First Scan

Run the full quality pipeline:

```bash
lucidshark scan --all
```

Example output when issues are found:

```
Total issues: 5

By severity:
  HIGH: 2
  MEDIUM: 2
  LOW: 1

By scanner domain:
  LINTING: 2
  TYPE_CHECKING: 2
  SCA: 1

Scan duration: 3412ms
```

For a detailed breakdown, use `--format table`:

```bash
lucidshark scan --all --format table
```

```
SEVERITY   ID                   DEPENDENCY                               TITLE
----------------------------------------------------------------------------------------------------
HIGH       CVE-2024-1234        lodash@4.17.20                           Prototype pollution in lodash
HIGH       TS2322               -                                        Type 'string' is not assignable to type 'number'
MEDIUM     no-unused-vars       -                                        'config' is defined but never used
MEDIUM     TS2345               -                                        Argument of type 'null' not assignable
LOW        no-console           -                                        Unexpected console statement

----------------------------------------------------------------------------------------------------
Total: 5 issues
By severity: high: 2, medium: 2, low: 1
```

When everything passes:

```
No issues found.
```

## Understanding Results

Each issue has:
- **Severity** -- `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
- **Domain** -- Which check found it (`LINTING`, `TYPE_CHECKING`, `SCA`, `SAST`, etc.)
- **ID/Rule** -- The specific rule (e.g., `no-unused-vars` for ESLint, `TS2322` for TypeScript, `CVE-2024-1234` for Trivy)
- **Dependency** -- For SCA findings, the vulnerable package and version

LucidShark returns exit code `1` when issues exceed your `fail_on` thresholds. Exit code `0` means all checks passed.

## Auto-Fix Linting Issues

ESLint and Biome both support auto-fixing. Run:

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

## Common TypeScript Tips

### Suppressing Linting Warnings (ESLint)

```typescript
// Suppress next line
// eslint-disable-next-line no-console
console.log("debug");

// Suppress on same line
console.log("debug"); // eslint-disable-line no-console

// Suppress for a block
/* eslint-disable no-console */
console.log("a");
console.log("b");
/* eslint-enable no-console */
```

### Suppressing Linting Warnings (Biome)

```typescript
// biome-ignore lint/suspicious/noExplicitAny: needed for legacy API
const data: any = fetchData();
```

### Suppressing Type Errors

```typescript
// Preferred: expect the error with a reason (TS 3.9+)
// @ts-expect-error: Legacy API returns string
const x: number = legacyApi();

// Suppress without reason (less preferred)
// @ts-ignore
const y: number = "hello";
```

### Skipping Tests (Jest)

```typescript
test.skip("not implemented", () => {
  // ...
});

describe.skip("feature suite", () => {
  // ...
});
```

### Istanbul Coverage Ignores

```typescript
/* istanbul ignore next */
if (process.env.NODE_ENV === "development") {
  enableDebugMode();
}
```

### Suppressing Security Findings

For dependency vulnerabilities (Trivy SCA), create a `.trivyignore` file:

```
# .trivyignore
CVE-2024-1234
```

For code security patterns (OpenGrep SAST):

```typescript
const secret = process.env.API_KEY; // nosemgrep: hardcoded-secret
```

See [Ignore Patterns](ignore-patterns.md) for the full reference.

## Adding to CI

Add LucidShark to your CI pipeline:

```yaml
# .github/workflows/quality.yml
name: Quality
on: [push, pull_request]

jobs:
  lucidshark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: npm ci
      - run: pip install lucidshark
      - run: lucidshark scan --all --all-files
```

LucidShark exits with code `1` when issues exceed thresholds, which fails the CI job.

## Next Steps

- [LLM Reference](help.md) -- Full CLI and configuration reference
- [Ignore Patterns](ignore-patterns.md) -- Detailed guide for excluding files and findings
- [Full Specification](main.md) -- Architecture and design documentation
