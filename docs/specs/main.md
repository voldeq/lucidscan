# LucidShark — Technical Specification

## 1. Problem Statement

Modern engineering teams build applications from multiple interconnected layers:

- **First-party application code**
- **Third-party open source dependencies**
- **Container images and base operating systems**
- **Infrastructure-as-code resources** (Terraform, Kubernetes, etc.)
- **AI-integrated components** such as MCP servers and tool-based automation

Security tooling across these layers is fragmented and inconsistent. Existing commercial platforms such as Snyk or SonarQube cover parts of the problem but introduce significant challenges:

- **Slow CI performance**: they are slow in CI pipelines, harming developer productivity.
- **Closed-source engines**: difficult to trust or validate their detection logic.
- **High cost**: often inaccessible to smaller companies.
- **Limited or complex self-hosting**: self-hosted options are limited or overly complex.
- **Noisy output**: they frequently overwhelm users with noisy or context-poor results when teams simply want actionable findings.

Meanwhile, excellent open-source scanners already exist across these domains — OSV-based SCA tools, Trivy for container scanning, Checkov for IaC, and Semgrep for static analysis. But in practice, using them individually leads to new challenges:

- **Incompatible outputs**: each scanner produces different, incompatible output formats.
- **Poor correlation**: results cannot be easily correlated or deduplicated.
- **Inconsistent severity**: severity and prioritization rules vary wildly between tools.
- **Fragmented workflow**: there is no unified workflow or command-line interface that ties them together.
- **Multiple dashboards**: developers must jump between multiple dashboards and CLIs to understand overall risk.
- **No single pane of glass**: there is no single place where all findings across code, dependencies, containers, and IaC are viewed in a consistent way.

At the same time, the rise of AI-connected systems (e.g., MCP servers) introduces new security considerations such as over-privileged tool access, unsafe data flows, and insecure endpoint configurations. These needs are not addressed by existing scanners but will soon become critical for many teams.

There is a clear need for a fast, transparent, self-hostable, open-source security platform that:

- **Performs SCA, container scanning, IaC scanning, and static code analysis (Semgrep) from day one.**
- **Unifies multiple proven open-source engines** behind a single CLI, consistent UX, and shared output schema.
- **Provides low-noise, actionable, developer-friendly results** suitable for local environments and CI/CD.
- **Avoids the opacity, complexity, and cost** of existing commercial platforms.
- **Can be extended in future versions** to include additional analysis domains such as SonarQube ingestion, advanced SAST rulesets, and AI/MCP configuration scanning without architectural changes.

This product aims to fill that gap by delivering an open, developer-first security scanner that covers code, dependencies, containers, and infrastructure from the start — while deliberately designing its architecture as a modular, pluggable scanning system capable of absorbing new security domains in future versions.

---

## 2. Goals

V1 of the product will deliver a unified, open-source, developer-friendly security scanner that integrates multiple proven scanning engines behind a single command-line interface, producing consistent, actionable results across the following domains.

### 2.1 Software Composition Analysis (SCA)

V1 will use **Trivy** as the primary open-source SCA engine, providing:

- **Dependency vulnerability scanning** for supported ecosystems (npm, yarn, pip, poetry, Go modules, Ruby gems, Cargo, etc.).
- **Automatic vulnerability database updates** (through Trivy’s built-in feeds: OSV, GHSA, distro advisories).
- **Detection of vulnerable packages**, including transitive dependencies.
- **Fix version suggestions** where available.
- **Local and CI scanning**.
- **Normalization** of Trivy’s SCA output into the unified issue schema.

There will be **no custom SCA matching logic in V1** — the product will rely on Trivy for accuracy and coverage.

### 2.2 Container Image Scanning

V1 will integrate Trivy’s container scanning capabilities to provide:

- **Detection of OS package vulnerabilities** in container images.
- **Detection of language dependency vulnerabilities** within container layers.
- **Basic config/secret checks** surfaced by Trivy.
- **Support for local image scanning and remote registry scanning.**
- **Normalization of container scan results** into the unified issue model.

This reuse of Trivy reduces integration complexity and ensures consistent vulnerability data across SCA and containers.

### 2.3 Infrastructure-as-Code (IaC) Scanning

V1 will integrate **Checkov** to provide:

- **Detection of insecure configurations** in Terraform, Kubernetes manifests, CloudFormation, and related IaC formats.
- **Severity-mapped findings** from Checkov rulesets.
- **Directory-based scanning.**
- **Normalization of IaC findings** into the unified issue schema.

Only **Checkov’s OSS rule set** will be used in V1.

### 2.4 Static Application Security Testing (SAST) via Semgrep

V1 will include **Semgrep** as the static analysis layer:

- **Running Semgrep** against the repository using community rulesets.
- **Detecting insecure coding patterns, misconfigurations, or bad practices.**
- **Normalizing Semgrep results** into the unified issue schema.
- **Supporting multiple programming languages** out of the box.
- **Running locally and inside CI.**

Custom rules may be supported later but are **not required for V1**.

### 2.5 Unified CLI

V1 will provide a single CLI that:

- Executes **SCA, container, IaC, and SAST scans** individually or together.
- Supports selective execution via flags.

Example flags:

- `--sca`
- `--container`
- `--iac`
- `--sast`
- `--all`

The CLI will:

- **Output standardized JSON** for all scanners.
- Support **human-readable formats** (table, summary).
- Work coherently in **local dev and CI/CD pipelines**.

The CLI will be the **primary interface** for V1.

### 2.6 Unified Issue Schema

V1 will define a consistent issue model with fields such as:

- **Scanner type** (`sca`, `container`, `iac`, `sast`).
- **Issue/vulnerability ID.**
- **Severity.**
- **Description.**
- **Affected file, package, resource, or container layer.**
- **Remediation or fix guidance** (when provided by underlying tool).
- **Metadata unique to scanner types** (e.g., dependency path, IaC resource).
- **Code snippet context** (Semgrep).

All engines must output in this **unified schema**.

### 2.7 CI/CD Integrations

V1 will ship with simple but functional CI integrations:

- **GitHub Action.**
- **GitLab CI template.**
- **Bitbucket Pipeline example.**
- **Exit codes** for pass/fail.
- **Support for JSON artifact export.**
- **Partial scans** (e.g., SCA only on dependency file changes).

### 2.8 Local Developer Experience

V1 will support:

- **CLI scanning during development.**
- **Fast execution paths** (e.g., skipping unchanged file scans where possible).
- A **config file** for scan settings (e.g., `.lucidscan.yml`).
- **Inline ignore/suppression rules** for findings.

### 2.9 Extensibility for Future Scanners

V1 will implement a **pluggable scanner architecture** so that future modules can be added without refactoring core components.

Examples of expected V2/V3 additions:

- **SonarQube ingestion.**
- **AI/MCP configuration scanning.**
- **Secret scanning.**
- **Advanced SAST policies.**
- **SBOM generation.**
- **DAST or runtime checks.**

This extensibility is a core architectural goal even if new scanners are not implemented until later versions.

### 2.10 AI Explanations and Mitigation Advice

V1 will add, at the end of each report, an **AI-generated explanation and mitigation advisory** for every reported issue:

- A **plain-language explanation** of the issue and its impact.
- A short **risk summary** (why it matters in practice).
- **Concrete mitigation steps** the user can take, including configuration or code-level changes where applicable.

These explanations are **advisory only** and do not modify code or configuration automatically.

---

## 3. Non-Goals (What V1 Will Not Do)

The following items are explicitly out of scope for V1. They may be implemented in later versions but will not be part of the initial release. Documenting these prevents scope creep and ensures the V1 timeline remains realistic for a solo founder.

### 3.1 No Custom SCA Engine or Vulnerability Database

V1 will **not** implement:

- Custom dependency resolution algorithms.
- Custom vulnerability matchers.
- A proprietary vulnerability database.
- Manual curation or enrichment of vulnerability data.

Instead, V1 relies fully on **Trivy** for SCA and vulnerability matching.

### 3.2 No Deep Container Analysis Beyond Trivy

V1 will **not** provide:

- Custom container parsing or SBOM generation.
- Custom OS package analysis.
- Proprietary heuristics around layered vulnerabilities.
- Runtime container scanning.

All container insights come from **Trivy**, normalized into the unified schema.

### 3.3 No Custom IaC Rule Engine

V1 will **not** include:

- Proprietary IaC rules.
- Custom policy languages.
- OPA/Rego-based rules.
- Cloud provider runtime checks.

IaC scanning is handled **exclusively by Checkov** in V1.

### 3.4 No Proprietary SAST Engine

V1 will **not** attempt to:

- Build its own static analysis engine.
- Maintain proprietary security rules.
- Analyze control-flow or data-flow beyond Semgrep capabilities.

V1 strictly integrates **Semgrep** as the SAST engine.

### 3.5 No Dashboard, UI, or Hosted SaaS Platform

V1 is **CLI-only** with CI integrations. V1 does **not** include:

- Web dashboard.
- Project history.
- Vulnerability trends.
- Reporting / governance views.
- Multi-user/team features.

These will be added in future releases once the core scanner stabilizes.

### 3.6 No Organizational Policy Engine

V1 will **not** implement:

- Policy-as-code.
- License compliance policies.
- Org-wide rulesets for vulnerability acceptance.
- Enforcement on PRs beyond basic exit codes.

These are **V2+ features**.

### 3.7 No Auto-Remediation or PR Generation

V1 will **not** include:

- Automatic pull request generation.
- Updating dependencies.
- Proposing code fixes.
- Rewriting IaC or config files.

Basic **“fix version available”** hints (from Trivy) will be surfaced but **not acted upon automatically**.

### 3.8 No SonarQube or SAST-Quality Integrations

V1 will **not** integrate:

- SonarQube.
- ESLint / Pylint / Flake8 / other quality tools.
- Runtime or dynamic analysis engines.

These are planned for **V2+**.

### 3.9 No AI Agentic Scanning or AI-Based Triage

V1 will **not** include:

- AI-driven triage that changes which issues are surfaced or how they are ordered.
- AI-based cross-project or cross-repository prioritization.
- Autonomous AI agents that take actions on behalf of the user (e.g., modifying code, configs, or CI pipelines).


### 3.10 No AI/MCP Server Security Scanning

Although support for AI/MCP configuration scanning is planned for later releases, V1 will **not** include:

- Parsing MCP configurations.
- Detecting unsafe tool definitions.
- Analyzing AI-agent system boundaries.
- Modeling LLM threat surfaces.

This will be introduced in **V2+**.

### 3.11 No Enterprise-Grade Features

V1 excludes:

- RBAC.
- SSO/SAML/OIDC.
- Audit logs.
- Multi-project/org management.
- Compliance reporting.

These will be added once the core scanning engine and unified model are validated.

---

## 4. Target Users

V1 targets **developers, DevOps engineers, and security practitioners** who need a fast, transparent, open-source security scanning tool that covers code, dependencies, containers, and IaC with minimal setup. The product is optimized for individuals and small-to-medium teams who want actionable results without the complexity, cost, or overhead of commercial platforms.

### 4.1 Primary Users (V1)

#### 4.1.1 Software Developers

Developers who want to:

- Run security scans locally during development.
- Quickly understand vulnerabilities without navigating multiple tools.
- Get clear, low-noise results.
- Avoid slow or heavy CI steps introduced by existing scanners.

**Motivation**: developers want tools that “just work” and don’t slow them down.

#### 4.1.2 DevOps / Platform Engineers

Engineers responsible for:

- Maintaining CI/CD pipelines.
- Managing container images.
- Validating IaC configurations.
- Ensuring security checks run consistently across environments.

**Motivation**: need a tool that is reliable, automation-friendly, and self-hostable.

#### 4.1.3 Security Engineers (AppSec / CloudSec)

Security professionals who:

- Need visibility across code, dependencies, containers, and IaC.
- Want to avoid vendor lock-in or closed-source tools.
- Prefer transparent, auditable scanners.
- Need unified data to build internal dashboards or policies.

**Motivation**: a single consistent source of truth across multiple domains.

### 4.2 Secondary Users (Not Fully Targeted in V1, but Supported)

#### 4.2.1 Open Source Maintainers

Developers who maintain packages or infrastructure templates and want:

- Fast scanning before releases.
- SCA + IaC checks across their repos.
- Minimal setup and friction.

#### 4.2.2 Small Security-Focused Consultancies

Consultants who need to:

- Run consistent scanning across client projects.
- Avoid expensive commercial licenses.
- Store results locally for compliance or audit reporting.

### 4.3 Future Users (V2+)

These users are relevant for product direction but are not the primary targets in V1.

#### 4.3.1 Larger Enterprises

Enterprises needing:

- Dashboards.
- SSO/RBAC.
- Compliance reporting.
- Organizational policies.
- Integrations with internal systems.
- Multi-project visibility.

These features will be addressed in future versions.

#### 4.3.2 Teams Using AI/MCP or Advanced SAST

Teams that require:

- AI agent infrastructure scanning.
- SonarQube ingestion.
- AI-based triage or auto-remediation.
- More advanced SAST or custom rule management.

These represent future product expansion areas.

### 4.4 User Assumptions for V1

For the initial release, we assume:

- Users are comfortable running CLI tools and using JSON outputs.
- Users have access to CI/CD and container environments.
- Users understand basic security concepts.
- Users are willing to configure minimal settings (e.g., `.lucidscan.yml`).
- Users accept that V1 is not a fully managed platform (no dashboard yet).

### 4.5 User Goals Summary

Across all personas, V1 is designed to help users:

- Detect vulnerabilities in dependencies, containers, IaC, and code.
- Run everything from **one command and one workflow**.
- Minimize noise and inconsistent results.
- Avoid the overhead and opacity of commercial tools.
- Integrate seamlessly into modern development pipelines.

---

## 5. Core Product Requirements (V1)

V1 will implement a unified security scanning tool that orchestrates multiple open-source engines (Trivy, Checkov, Semgrep) behind a single CLI and produces consistent, actionable results. The requirements below define the expected behavior of the system.

### 5.1 General Requirements

#### 5.1.1 Single Command-Line Interface

The product MUST provide one CLI executable that can run:

- SCA scans.
- Container scans.
- IaC scans.
- SAST scans.
- Any combination (e.g., `--all`).

The CLI should follow intuitive, **UNIX-style patterns**.

#### 5.1.2 Consistent Output

All scan results MUST be converted into a unified JSON schema, regardless of scanner source.

Key requirements:

- Normalized severity levels (e.g., `low` / `medium` / `high` / `critical`).
- Consistent field names.
- Consistent structure.
- Ability to emit both **machine-readable and human-friendly output**.
- No underlying scanner’s native format should be exposed to the user unless explicitly requested.

#### 5.1.3 Fast Execution

V1 MUST optimize for minimal scanning time by:

- Reusing scanner binaries when possible.
- Caching scanner downloads.
- Running appropriate scanners only when relevant files are present.

**Goal**: developer-friendly speed, especially in CI.

#### 5.1.4 Exit Codes for CI/CD

The CLI MUST support meaningful exit codes:

- `0` — no issues found.
- `1` — issues found with severity ≥ threshold.
- `2` — internal error.

The **exit code threshold MUST be configurable.**

#### 5.1.5 Local Development Support

The tool MUST work seamlessly in developer environments:

- Local CLI installation.
- Scanning partial directories.
- Ignoring/suppressing findings via config.
- Fast partial scans.

#### 5.1.6 Zero External Dependencies (Except Scanners)

The CLI MUST not require:

- A cloud backend.
- User accounts.
- Internet connectivity (after scanner DB is cached).

### 5.2 SCA Requirements (Using Trivy)

#### 5.2.1 Supported Ecosystems

V1 MUST support the ecosystems that Trivy supports out-of-the-box, including:

- Node.js (npm, yarn).
- Python (pip, pipenv, poetry).
- Go modules.
- Ruby (bundler).
- Rust (cargo).
- Java JAR-level vulnerability detection.
- Others as supported by Trivy.

#### 5.2.2 Vulnerability Detection

SCA MUST detect:

- Direct dependency vulnerabilities.
- Transitive dependency vulnerabilities.
- Fix versions.
- CVE/OSV/GHSA references.

#### 5.2.3 Output Normalization

SCA results MUST be normalized to common fields such as:

- Package name.
- Installed version.
- Fixed version.
- Severity.
- Dependency path.
- Vulnerability ID.
- Description and links.

### 5.3 Container Scanning Requirements

#### 5.3.1 Supported Targets

The tool MUST support scanning:

- Local Docker images.
- Remote registry images (Docker Hub, ECR, GCR, etc.).

#### 5.3.2 Vulnerability Detection

Container scanning MUST include:

- OS-level package vulnerabilities.
- Language-level vulnerabilities within container layers.

#### 5.3.3 Output Normalization

Container findings MUST map to unified schema fields like:

- Image reference.
- File/layer path.
- Installed package.
- Severity.
- CVE/OSV/GHSA ID.

### 5.4 IaC Scanning Requirements (Using Checkov)

#### 5.4.1 Supported Formats

V1 MUST support scanning:

- Terraform.
- Kubernetes manifests.
- CloudFormation.
- Helm templates (where possible).

#### 5.4.2 Detection

IaC scans MUST detect:

- Insecure config patterns.
- Missing encryption.
- Open network access.
- Privilege escalation risks.
- Misconfigured IAM policies.

#### 5.4.3 Output Normalization

IaC results MUST include:

- File and line reference.
- Rule ID.
- Severity.
- Resource name.
- Remediation summary.

### 5.5 SAST Requirements (Using Semgrep)

#### 5.5.1 Supported Languages

Whatever Semgrep supports by default in OSS rulesets MUST be supported in V1.

#### 5.5.2 Rule Selection

V1 MUST:

- Run with a baseline community ruleset.
- Allow users to override rulesets via config.

#### 5.5.3 Output Normalization

SAST results MUST include:

- Rule ID.
- File and line position.
- Extracted code snippet context.
- Severity.
- Message / description.

### 5.6 Configuration Requirements

#### 5.6.1 Config File

The tool MUST support an optional config file `.lucidscan.yml` including:

- Enabled/disabled scanners.
- Ignore rules.
- Severity threshold.
- Custom Semgrep ruleset path.
- CI behavior options.

#### 5.6.2 Inline Ignores

V1 MUST support inline ignore annotations (where supported by scanner), such as:

- Semgrep inline comments.
- Checkov skip annotations.
- Custom ignore IDs.

### 5.7 Extensibility Requirements

#### 5.7.1 Pluggable Architecture

The system MUST be designed so new scanners can be added with:

- Minimal changes to the core CLI.
- Standard input/output handlers.
- Standardized JSON mapping logic.

#### 5.7.2 No Coupling to Trivy/Checkov/Semgrep Internals

The integration MUST remain bounded by:

- Calling binaries.
- Using CLI flags.
- Parsing JSON.

This ensures future replacements or alternates (e.g., Grype, tfsec, SonarQube) can be plugged in easily.

### 5.8 Error Handling Requirements

- Meaningful error messages MUST be provided.
- CLI MUST distinguish between scanner failure and scan findings.
- Partial scans MUST still return structured output when possible.

### 5.9 Logging Requirements

V1 MUST support:

- Quiet mode.
- Verbose debug mode.
- Structured logging for CI troubleshooting.

### 5.10 Documentation Requirements

V1 MUST include:

- Installation instructions.
- CLI usage examples.
- Integration examples (GitHub, GitLab).
- Configuration examples.
- Explanation of unified schema.

---

## 6. System Architecture Overview (Thick CLI + Bundled Tools — V1 Architecture)

V1 uses a **thick CLI** execution model. The `lucidscan` CLI process runs all orchestration and scanning logic **locally on the user's machine**, using bundled copies of Trivy (binary), Semgrep, and Checkov (both pip-installed into a bundled Python venv). There is **no remote scan server in V1**: source code is never uploaded, and all analysis happens on the local filesystem (or inside a CI container).

The CLI is installed via `pip install lucidscan` on developer machines. On first run, it bootstraps a local tool bundle under `~/.lucidscan` and reuses that bundle across subsequent runs. In CI, an official Docker image is used instead of `pip install` to ensure fast, reproducible scans.

### 6.1 High-Level Architecture

At a high level, `lucidscan` consists of a single process that orchestrates multiple local scanners and post-processing layers:

```text
+--------------------------------------------------+
|                 lucidscan CLI (Python)             |
+--------------------------------------------------+
|                Orchestrator                      |
|  - Scan configuration & routing                  |
|  - Parallel scanner execution where appropriate  |
---------------------------------------------------+
|              Scanner Adapters                    |
|  - Trivy (SCA + containers)                      |
|  - Checkov (IaC via bundled venv)                |
|  - Semgrep (SAST via bundled venv)               |
---------------------------------------------------+
|              Normalization Layer                 |
|  - Raw scanner JSON → Unified Issue Schema       |
---------------------------------------------------+
|              Aggregation Layer                   |
|  - Merge issues, summaries, metadata             |
---------------------------------------------------+
|        AI Advisory / Explanation Layer           |
|  - Optional per-issue explanation & mitigation   |
---------------------------------------------------+
|                Output Renderer                   |
|  - JSON | Table | Summary                        |
+--------------------------------------------------+
                 |
                 v
+--------------------------------------------------+
|              Local Tool Bundle (~/.lucidscan)      |
+--------------------------------------------------+
| bin/        → trivy binary                       |
| venv/       → Python 3.11 venv with semgrep,     |
|               checkov pip-installed              |
| cache/      → trivy/ vulnerability DB            |
| config/     → optional global config             |
| logs/       → debug / diagnostics (optional)     |
| versions.json → pinned scanner + bundle versions |
+--------------------------------------------------+
```

All components shown above run **in-process** within the CLI, invoking local binaries or environments from `~/.lucidscan`. There is no REST API, job queue, or remote worker layer in V1.

### 6.2 CLI & Local Execution Model

The CLI binary (`lucidscan`) acts as the user entry point and is responsible for:

- Parsing command-line flags.
- Loading local and project configuration (e.g., `.lucidscan.yml` in the repo, and optional global settings under `~/.lucidscan/config`).
- Discovering the project root and effective scan set (respecting ignore rules).
- Constructing an in-memory `ScanRequest` object (enabled scanners, paths, thresholds).
- Running the **local orchestrator** and scanner adapters against the project tree.
- Rendering the resulting `ScanResult` in the requested output format (JSON, table, summary).
- Setting exit codes based on severity thresholds.

Example CLI usage:

```bash
lucidscan --all
lucidscan --sca --sast
lucidscan --format json
lucidscan --severity-threshold high
```

The CLI is **self-contained**: once the tool bundle has been downloaded, it does not require any remote scan server for normal operation.

### 6.3 Project Discovery & File Selection

This section describes how the CLI identifies what to scan on the local filesystem. All operations in this section are purely local; no code or metadata is uploaded.

#### 6.3.1 Project Root Identification

On each scan, the CLI MUST:

- **Identify the project root**
  - Start from the current working directory.
  - Optionally use heuristics (e.g., presence of `package.json`, `pyproject.toml`, `.git`, etc.) or an explicit `--project-root` flag.
- **Support monorepos and subdirectories**
  - Allow scanning either the entire repo or a subdirectory (e.g., `lucidscan --path services/api`).

The resolved project root and scan path are passed to the orchestrator and scanner adapters.

#### 6.3.2 Ignore Rules & Effective Scan Set

The CLI computes an **effective scan set** of files and directories by applying multiple layers of ignore rules:

- **Project-level ignore file**
  - Respect a project-specific ignore file (e.g., `.lucidscanignore`) for excluding paths and file patterns from scans.
- **VCS ignores**
  - Fall back to `.gitignore` rules when applicable to avoid scanning build artifacts and generated content.
- **CLI-level excludes**
  - Support additional excludes via flags (e.g., `--exclude node_modules/`, `--exclude dist/`, large binary directories).

Scanner adapters receive only the effective scan set, reducing noise and improving performance.

#### 6.3.3 Security Considerations (Local-Only)

Project discovery and file selection MUST adhere to the following security properties:

- **Local-only analysis**
  - Source code and configuration files are read from the local filesystem (or CI container filesystem) only.
  - No code upload, REST calls with source archives, or remote job submission occurs in V1.
- **Read-only operation**
  - Scanners and the CLI treat the project directory as read-only; they MUST NOT modify code or configuration files.
- **Sensitive content handling**
  - Users can explicitly exclude paths that contain highly sensitive data via `.lucidscanignore` and CLI flags.

### 6.4 Local Orchestrator

The orchestrator is the core control component running **inside the CLI process**. It is responsible for:

#### 6.4.1 Scanner Selection

Based on:

- CLI flags (e.g., `--sca`, `--sast`, `--all`).
- `.lucidscan.yml`.
- Optional automatic project detection (e.g., only run Semgrep if source files exist).

#### 6.4.2 Building Scan Context

The orchestrator builds a `ScanContext` that includes:

- Target directory / repository path on the local filesystem.
- Effective scan set after ignore rules.
- Config overrides (from CLI and config files).
- Selected scanners and their configuration.
- Environment variables relevant to scanners (e.g., proxy settings).
- Paths to bundled scanner binaries and environments under `~/.lucidscan`:
  - `~/.lucidscan/bin/trivy` (Trivy binary).
  - `~/.lucidscan/venv/bin/semgrep` (pip-installed in bundled venv).
  - `~/.lucidscan/venv/bin/checkov` (pip-installed in bundled venv).

#### 6.4.3 Executing Scanner Adapters

The orchestrator calls the adapter for each enabled scanner:

```text
adapter.scan(context) => RawScannerResult
```

Execution characteristics:

- Scanners MAY be run **in parallel** when system resources allow, to reduce total scan time.
- Each adapter invokes its tool using the **bundled binaries/environments** from `~/.lucidscan`, never from system PATH.

#### 6.4.4 Collecting Raw Outputs

The orchestrator collects per-scanner metadata:

- Raw JSON outputs.
- Scanner versions (from `versions.json` and tool `--version` output).
- Execution time per scanner.
- Exit codes and any error messages.

This raw data is then passed to the **Normalization Layer**.

### 6.5 Scanner Adapters

Each scanner is wrapped by an adapter that abstracts away its CLI interface and enforces consistent behavior.

#### 6.5.1 `TrivyAdapter`

Handles:

- SCA scans via `trivy fs` (using the bundled `trivy` binary).
- Container scans via `trivy image`.

Responsibilities:

- Ensure JSON output (`-f json`).
- Use the Trivy cache directory under `~/.lucidscan/cache/trivy`.
- Normalize exit codes for orchestration.

#### 6.5.2 `CheckovAdapter`

Handles:

- IaC scans for Terraform, Kubernetes, CloudFormation, etc.

Responsibilities:

- Run Checkov from the bundled venv at `~/.lucidscan/venv/bin/checkov`.
- Call `checkov -o json`.
- Apply ignore rules based on config.
- Capture file/line/resource metadata.

#### 6.5.3 `SemgrepAdapter`

Handles:

- SAST scanning across supported languages.

Responsibilities:

- Run Semgrep from the bundled venv at `~/.lucidscan/venv/bin/semgrep`.
- Execute `semgrep --config <ruleset> --json`.
- Optionally detect languages automatically.
- Capture rule metadata and code snippet context.

### 6.6 Normalization Layer

Each scanner outputs different JSON schemas, so the normalization layer:

- Converts raw results into a **Unified Issue Schema**.
- Maps severity levels into consistent categories: `low | medium | high | critical`.
- Extracts common fields (rule ID, file, line, message, remediation).
- Preserves scanner-specific metadata under a generic `extra` field.

Example unified issue:

```json
{
  "scanner": "sca",
  "sourceTool": "trivy",
  "id": "CVE-2025-1234",
  "severity": "high",
  "title": "Vulnerability in express",
  "description": "Arbitrary code execution...",
  "location": {
    "file": "package.json",
    "package": "express",
    "version": "4.17.1"
  },
  "remediation": {
    "fixVersion": "4.18.0"
  }
}
```

Each adapter has a corresponding normalization function:

- `normalizeTrivySca()`
- `normalizeTrivyContainer()`
- `normalizeCheckov()`
- `normalizeSemgrep()`

### 6.7 Aggregation Layer

The aggregation layer merges all normalized issues into a single output.

Responsibilities:

- Combine issues from all scanners.
- Remove duplicates or overlaps where applicable.
- Compute summary statistics:
  - Total issues.
  - Issues per severity.
  - Issues per scanner.
- Attach metadata:
  - Scanner versions.
  - Scan duration.
  - Trivy DB updated timestamp.
- Produce final `ScanResult` object.

Example:

```json
{
  "issues": [],
  "summary": {
    "total": 42,
    "bySeverity": { "critical": 2, "high": 10, "medium": 20, "low": 10 },
    "byScanner": { "sca": 25, "container": 5, "iac": 8, "sast": 4 }
  },
  "metadata": {
    "startedAt": "2025-01-01T10:00:00Z",
    "finishedAt": "2025-01-01T10:00:07Z",
    "durationMs": 7123,
    "scanners": [
      { "name": "trivy", "version": "0.58.1", "dbUpdatedAt": "2025-01-01T07:00:00Z" },
      { "name": "checkov", "version": "3.2.346" },
      { "name": "semgrep", "version": "1.102.0" }
    ]
  }
}
```

### 6.8 AI Advisory Layer (Explanations & Mitigation Advice)

The AI advisory layer is an **optional component inside the CLI process** that runs **after** the Aggregation Layer and **before** the Output Renderer. It is responsible for enriching the unified issues with human-readable explanations and mitigation guidance as described in **2.10 AI Explanations and Mitigation Advice**.

Responsibilities:

- Take the aggregated `ScanResult` (issues + summary) as input.
- For each issue, generate:
  - A plain-language explanation of the issue and its impact.
  - A short risk summary (why it matters in practice).
  - Concrete mitigation steps (configuration or code-level, where applicable).
- Attach these fields to each issue in the unified schema (e.g., `aiExplanation`, `aiRiskSummary`, `aiMitigationSteps`) or as a separate `aiAdvisories` section in the result.

Constraints:

- The AI advisory layer is **advisory only** and MUST NOT:
  - Modify source code, configuration, or infrastructure.
  - Change issue severities, filtering, or ordering.
  - Suppress or re-rank issues (see **3.9 No AI Agentic Scanning or AI-Based Triage**).
- The AI advisory layer MAY be disabled via configuration (e.g., CLI flag or `.lucidscan.yml`) so that fully offline or air-gapped deployments can run without any AI backend.
- When disabled, the orchestrator bypasses this layer and returns the raw aggregated issues directly to the Output Renderer.

The actual LLM or AI backend (local model vs. remote service) is configured separately and is not coupled to scanner execution or orchestration.

### 6.9 Output Renderer

The Output Renderer converts `ScanResult` (including any AI-enriched fields when enabled) into user-facing formats:

- **JSON** (full result, including AI explanations/mitigations when present).
- **Table** (human friendly).
- **Summary** (high-level stats plus concise advisory text when available).

Also:

- Prints messages clearly to stdout/stderr.
- Applies severity threshold for exit codes.
- Optionally writes output to files when requested.

Exit code logic:

- `0` → no issues above threshold.
- `1` → issues found.
- `2` → internal error.

### 6.10 Tool Installation, Local Layout, and Caching

V1 standardizes how scanners are installed and used to maximize reproducibility.

#### 6.10.1 Developer Installation (pip)

On developer machines:

- Users install the CLI via:

  ```bash
  pip install lucidscan
  ```

- This installs only the Python CLI code. On first run, the CLI:
  - Detects OS and architecture (e.g., `linux/amd64`, `linux/arm64`, `darwin/arm64`).
  - Downloads a **scanner tool bundle** from a hosted URL appropriate for that platform.
  - Verifies and unpacks the bundle into `~/.lucidscan`.

#### 6.10.2 `~/.lucidscan` Directory Layout

The local tool bundle is organized as follows:

- `~/.lucidscan/bin/`
  - `trivy` — bundled Trivy binary for the platform.
- `~/.lucidscan/venv/`
  - A self-contained Python 3.11 virtual environment that includes:
    - Semgrep (pip-installed).
    - Checkov (pip-installed).
    - All required Python dependencies.
- `~/.lucidscan/cache/trivy/`
  - Trivy vulnerability database and related cache files.
- `~/.lucidscan/config/` (optional)
  - Global configuration overrides (e.g., default severity threshold, default scanners).
- `~/.lucidscan/logs/` (optional)
  - Diagnostic and debug logs.
- `~/.lucidscan/versions.json`
  - Pinned versions for:
    - Trivy, Semgrep, Checkov, Python.
    - The bundle format version and platform.
    - Any auxiliary data files.

The CLI **always uses these bundled tools** instead of any system-installed binaries on PATH.

#### 6.10.3 Vulnerability Data & Caching

Vulnerability database management is handled locally by Trivy:

- Trivy stores its DB under `~/.lucidscan/cache/trivy`.
- On first SCA/container scan, Trivy may need to download or update its DB.
- Subsequent scans reuse the cached DB, making runs significantly faster.

Reproducibility considerations:

- `versions.json` pins the compatible scanner versions for a given CLI release.
- The CLI and CI Docker image both reference `versions.json` to ensure consistent behavior across environments.

### 6.11 Docker Image for CI

Developer machines DO NOT need Docker to use `lucidscan`. However, for CI/CD environments, V1 provides an official Docker image to ensure fast, reproducible scans without bootstrapping tools on every run.

Characteristics:

- Image name: `ghcr.io/you/lucidscan:latest` (example).
- Contains:
  - The `lucidscan` CLI.
  - Bundled Trivy binary.
  - Bundled Python venv with Semgrep and Checkov.
  - Optionally, a pre-warmed Trivy DB in the expected cache location.

Example CI snippet (generic YAML-style):

```yaml
image: ghcr.io/you/lucidscan:latest

steps:
  - name: Run security scan
    script:
      - lucidscan --all --format json --severity-threshold high
```

Guidance:

- **Developer machines**: install with `pip install lucidscan` and let the CLI manage `~/.lucidscan`.
- **CI environments**: use the official Docker image instead of installing via `pip` for speed and consistency.

### 6.12 Extensibility Model and Future Server Mode

The architecture treats each scanner as a module with:

- An adapter.
- A normalization function.
- Metadata describing capabilities.

Adding future scanners such as:

- Secret scanners.
- SonarQube ingestion.
- AI/MCP config analysis.
- SBOM generation.

…requires minimal changes to orchestrator code.

Although earlier iterations considered a remote server mode, **V1 is strictly local-only**. A future version (V2+) MAY introduce an optional server/orchestrator mode (for centralized scanning, policy enforcement, or large multi-repo environments), but that is out of scope for this design and will not change the core thick-CLI and bundled-tools model described above.

## 7. Data Sources & Vulnerability Ingestion (Thick CLI Architecture)

In the thick-CLI architecture, all scanning, vulnerability ingestion, rule loading, and updates occur locally on the developer’s machine. There is no remote server and no code ever leaves the local environment. The CLI bundles or bootstraps all required scanning engines (Trivy, Checkov, Semgrep) and manages their versions independently from the system environment.

The CLI’s responsibility is to provide a predictable, reproducible, and self-contained scanning environment with zero external tooling requirements beyond the initial installation of the `lucidscan` Python package.

### 7.1 Overview of Ingestion Model

All vulnerability data comes from the open-source scanning engines that `lucidscan` orchestrates:

- **Trivy**: vulnerability databases for OS packages and SCA.
- **Checkov**: IaC rulepacks for Terraform, Kubernetes, CloudFormation.
- **Semgrep**: SAST rulesets for source code analysis.

`lucidscan` does not maintain its own vulnerability database in V1. Instead, it relies on the upstream scanners to download and maintain their own rulepacks or vulnerability feeds.

All ingestion processes happen inside the user’s local runtime:

`lucidscan → orchestrator → local tools → raw results → normalization → unified output`

There is no dependency on external APIs, server components, or cloud services.

### 7.2 Tool and Rule Source Breakdown

#### 7.2.1 Trivy (SCA + Container Vulnerabilities)

Trivy loads the following vulnerability feeds locally:

- **OSV (Open Source Vulnerabilities)**.
- **GHSA (GitHub Security Advisories)**.
- **NVD (National Vulnerability Database)**.
- **Linux distribution feeds** (Debian, Alpine, Ubuntu, etc.).
- **Language ecosystem advisories** (npm, PyPI, Go modules, etc.).

Trivy maintains its vulnerability DB under:

- `~/.lucidscan/cache/trivy/db`

`lucidscan` ensures Trivy uses this directory so the DB is downloaded once and reused across all scans.

#### 7.2.2 Checkov (IaC Misconfiguration Analysis)

Checkov uses:

- Built-in IaC policies included in the Checkov distribution.
- Terraform/Kubernetes/CloudFormation schema validation rules.
- No external vulnerability DB.

Checkov’s rules remain static unless the tool itself is updated. `lucidscan` keeps Checkov inside a packaged Python virtual environment to ensure deterministic behavior regardless of the system Python installation.

#### 7.2.3 Semgrep (SAST Rulesets)

Semgrep uses:

- Built-in core rules.
- Optionally downloaded community rulepacks.
- Local `.semgrep.yml` files if present.

Semgrep maintains a small cache for downloaded rulepacks under:

- `~/.lucidscan/cache/semgrep`

Rule ingestion is lightweight and safe to run as part of a local scan.

### 7.3 Ingestion Lifecycle (Local Execution)

The ingestion process per scan follows these steps:

1. **User runs a scan**:

   ```bash
   lucidscan --all
   ```

2. **`lucidscan` locates the bundled tools** under:

   - `~/.lucidscan/bin` (Trivy binary)
   - `~/.lucidscan/venv` (Python venv with Semgrep and Checkov)

3. **For each scanner**:

   - Trivy updates its local vulnerability DB (unless fresh or explicitly disabled).
   - Checkov loads its built-in rulepacks.
   - Semgrep loads rulepacks or uses local cached copies.

4. **Each scanner produces raw JSON output.**

5. **`lucidscan` normalizes** the raw results into the unified issue schema.

6. **Final structured output is rendered** in human-readable and/or JSON format.

All work takes place on the local machine (or inside the CI container).

### 7.4 Vulnerability Database Management (Trivy)

Trivy downloads and updates its vulnerability database automatically.

`lucidscan` ensures:

- The DB is cached under `~/.lucidscan/cache/trivy/`.
- The DB is reused across all scans.
- The DB is not downloaded unnecessarily.

Users can optionally disable DB updates:

```bash
lucidscan --skip-db-update
```

The first Trivy run may take several seconds to download the DB; subsequent runs use the cached DB and are fast.

### 7.5 Reproducibility & Version Pinning

To ensure reproducibility:

- `lucidscan` tracks scanner versions in:
  - `~/.lucidscan/config/versions.json`

Each scan result includes metadata such as:

- `lucidscan` version.
- Trivy version and DB update timestamp.
- Checkov version.
- Semgrep version.

Users can upgrade tools when `lucidscan` is upgraded via:

```bash
pip install --upgrade lucidscan
lucidscan --update-tools
```

This allows consistent results across machines and CI.

### 7.6 Offline & Air-Gapped Support

Because ingestion is local:

- Offline scanning is fully supported once tools and DBs are installed.
- Trivy DB can be pre-fetched and transported manually.
- Checkov and Semgrep require no network access after installation.
- Companies in air-gapped or regulated environments can use `lucidscan` without modification.
- Organizations that need strict offline readiness can optionally bundle a pre-warmed Trivy DB.

### 7.7 Security & Privacy Considerations

No code ever leaves the local machine.

Because scanning runs locally and ingestion occurs from local caches:

- No code is uploaded anywhere.
- No remote server sees user data.
- No external API calls occur during scanning.
- The only network activity is optional vulnerability DB updates from Trivy’s open-source feeds.

This satisfies:

- Privacy-sensitive users.
- Enterprises with strict policies.
- Offline environments.

### 7.8 Responsibilities Summary

#### 7.8.1 `lucidscan` (CLI) responsibilities

- Manage bundled tools.
- Ensure correct versioning and reproducibility.
- Trigger Trivy / Checkov / Semgrep with local paths.
- Maintain local caches.
- Normalize results.
- Produce unified output.

#### 7.8.2 External scanner responsibilities

- Download and apply vulnerability feeds (Trivy).
- Provide rulepacks (Checkov, Semgrep).
- Detect vulnerabilities and misconfigurations.
- Emit machine-readable JSON for `lucidscan`.


## 8. Dependency Resolution Strategy

This section defines how `lucidscan` identifies, resolves, and analyzes open-source dependencies across supported languages and package ecosystems. In the thick-CLI architecture, all dependency resolution is performed locally using the bundled Trivy engine. The CLI acts as the orchestrator but delegates the heavy lifting of dependency discovery, graph expansion, and vulnerability matching to Trivy.

The goal of this strategy is to support multi-language repositories with minimal configuration, predictable performance, and consistent output across environments.

### 8.1 Overview

Dependency resolution determines:

- Which manifests exist in the project.
- What dependencies they declare.
- How transitive dependencies are affected.
- Which vulnerabilities apply to each dependency.

`lucidscan` does not implement its own resolver. It relies entirely on Trivy’s built-in SCA analyzers, which support a wide range of ecosystems.

`lucidscan`:

- Discovers relevant manifest files.
- Invokes Trivy with the correct context.
- Collects Trivy’s resolved dependency graph and vulnerability matches.
- Converts results into the unified issue schema.

This ensures correctness and full alignment with a trusted, actively maintained vulnerability scanning engine.

### 8.2 Supported Dependency Ecosystems (via Trivy)

Trivy supports many ecosystems. `lucidscan` inherits them automatically.

**Package Managers**

- **npm / yarn / pnpm**: `package.json`, `package-lock.json`, `yarn.lock`.
- **Python (pip/poetry)**: `requirements.txt`, `Pipfile.lock`, `poetry.lock`.
- **Ruby (bundler)**: `Gemfile.lock`.
- **Rust**: `Cargo.lock`.
- **Go**: `go.mod` (via module graph resolution).
- **Java**: `pom.xml`, `gradle.lockfile`.
- **PHP**: `composer.lock`.
- **.NET**: `packages.lock.json`.
- And others supported by the current Trivy release.

**Container Base Image Dependencies**

Container scanning also produces dependency insights, but those are handled in the container-scanning sections.

### 8.3 Project Scanning Flow

The dependency resolution flow is:

#### Step 1 — `lucidscan` detects supported manifests

On startup, the CLI recursively searches the project root for known manifest files.

Examples:

- `package.json`
- `yarn.lock`
- `go.mod`
- `Cargo.lock`
- `pom.xml`
- Terraform files (ignored for SCA)

Ignore logic is applied (e.g., skip `node_modules/`, `.lucidscanignore`, `.git/`).

#### Step 2 — `lucidscan` invokes Trivy in filesystem mode

Example invocation (abstracted):

```bash
trivy fs --security-checks vuln --format json <project-root>
```

This triggers Trivy’s built-in resolvers:

- Ecosystem-specific dependency extraction.
- Graph walking.
- Version normalization.
- (Future) License matching.
- Vulnerability matching via local Trivy DB.

#### Step 3 — Trivy produces a resolved dependency graph

Trivy outputs, for each ecosystem:

- Dependency name.
- Installed version.
- Dependency path/chains.
- Transitive relationships.
- Vulnerability list.
- Fixed version information.

#### Step 4 — `lucidscan` normalizes results

Results are mapped into `lucidscan`’s unified issue schema:

For each vulnerable dependency:

- `scanner`: `sca`.
- `sourceTool`: `trivy`.
- `ecosystem`: `npm` / `python` / `go` / `ruby` / etc.
- Dependency metadata.
- Vulnerability metadata (CVE, severity, fix versions).
- Code location (manifest file path).
- Dependency chain (optional field).

### 8.4 Multi-Language Repository Support

Modern repos may contain:

- Frontend (npm).
- Backend (Python or Go).
- Shared modules.
- Container images.
- IaC.

Trivy automatically detects each ecosystem independently.

`lucidscan` aggregates all dependency issues together into a single final `ScanResult`:

- No configuration required.
- Developers do not need to specify project type.

### 8.5 Handling Multiple Manifests

If multiple manifests of the same type exist (e.g., multiple microservices):

```text
services/
  api/package.json
  worker/package.json
```

`lucidscan`:

- Treats each manifest independently.
- Invokes Trivy once for the entire directory.
- Relies on Trivy to resolve all manifests recursively.
- Keeps issues grouped by manifest path in the normalized output.

This allows monorepos and polyrepos to work seamlessly.

### 8.6 Handling Large Dependency Graphs

Trivy supports:

- Caching.
- Parallel resolution.
- (Future) Incremental scanning.

`lucidscan` ensures speed by:

- Using local package manager lockfiles where available (fast path).
- Skipping directories via a unified ignore system.
- Enabling Trivy cache reuse under `~/.lucidscan/cache/trivy/db`.

On large JavaScript or Java projects, caching the Trivy DB locally significantly improves performance.

### 8.7 Limitations & Known Constraints

While Trivy is powerful, dependency resolution has some natural limitations:

1. **Incomplete lockfiles**
   - If a lockfile is missing, Trivy may fall back to best-effort graph generation, which may:
     - Produce partial results.
     - Miss some transitive dependencies.

2. **Non-standard dependency managers**
   - Custom or obscure ecosystems (e.g., Bazel, Buck) may not be supported.

3. **Runtime-only dependencies**
   - Dynamic imports or runtime-installed dependencies (e.g., `pip install` executed inside application code) cannot be accounted for.

4. **Vendor directories**
   - If `vendor/` directories exist, they may be skipped or duplicated unless explicitly excluded.

5. **Git submodules**
   - Trivy scans submodules as normal directories; `lucidscan` requires `.lucidscanignore` to customize behavior.

These limitations should be documented clearly for users.

### 8.8 Reproducibility

Dependency vulnerability results depend on:

- Exact dependency versions (from lockfiles).
- Trivy version.
- Trivy DB updated timestamp.

`lucidscan` includes all three in output metadata.

Developers can disable DB updates for audit-mode scans:

```bash
lucidscan --skip-db-update
```

This ensures deterministic scanning.

### 8.9 Future Enhancements

Future improvements may include:

- SBOM generation via Trivy (CycloneDX / SPDX).
- Enhanced dependency chain visualization.
- License policy enforcement.
- Deeper integration with the AI explanation engine for remediation context.
- More precise reachability analysis (combining SAST + SCA signals).


## 9. Unified Issue Schema

`lucidscan` integrates multiple heterogeneous security scanners, each producing its own JSON representation, severity conventions, metadata fields, and terminology. To deliver a consistent developer experience and enable future features such as AI explanations, dashboards, and policy enforcement, `lucidscan` normalizes all findings into a **Unified Issue Schema (UIS)**.

The UIS is designed to:

- Represent all scanners uniformly.
- Preserve scanner-specific details.
- Simplify consumption by other tools.
- Support optional future extensions.
- Enable reproducible and machine-readable output.

This section defines the schema used internally and in output formats (e.g., `--format json`).

### 9.1 Design Goals

The schema must support:

- **Cross-scanner compatibility**
  - SAST (Semgrep), SCA (Trivy), and IaC (Checkov) should be mappable.
- **Minimal but expressive field set**
  - It should be easy to understand and easy to extend.
- **Structured machine-readable data**
  - Required for automation, CI gates, AI remediation, and dashboards.
- **Preservation of original scanner data**
  - To ensure traceability and debugging.
- **Stable and versioned schema**
  - Backward compatibility lives under `schemaVersion`.

### 9.2 Top-Level Structure

Each scan returns a `ScanResult`:

```json
{
  "schemaVersion": "1.0",
  "issues": [ { "...Issue..." } ],
  "metadata": {
    "lucidscanVersion": "0.7.0",
    "trivyVersion": "0.58.1",
    "trivyDbUpdatedAt": "2025-01-10T12:00:00Z",
    "semgrepVersion": "1.102.0",
    "checkovVersion": "3.2.346",
    "scanStartedAt": "...",
    "scanFinishedAt": "...",
    "projectRoot": "/path/to/project"
  }
}
```

The core information resides in the `issues` array.

### 9.3 Issue Object Schema

Each issue conforms to the following structure:

```json
{
  "id": "unique-issue-id",
  "scanner": "sca|sast|iac",
  "sourceTool": "trivy|semgrep|checkov",
  "severity": "critical|high|medium|low|info",
  "title": "...",
  "description": "...",
  "filePath": "src/app/main.py",
  "lineStart": 17,
  "lineEnd": 17,
  "dependency": null,
  "iacResource": null,
  "codeSnippet": null,
  "recommendation": null,
  "scannerMetadata": { }
}
```

Fields vary by scanner type.

### 9.4 Field-by-Field Definition

#### 9.4.1 `id`

A deterministic issue ID, stable across runs when the underlying issue is unchanged.

Generated via hashing:

```text
sourceTool + filePath + lineStart + ruleId + (dependencyName if applicable)
```

#### 9.4.2 `scanner`

High-level category:

- `sca` → Trivy.
- `sast` → Semgrep.
- `iac` → Checkov.

#### 9.4.3 `sourceTool`

The underlying tool:

- `trivy`
- `semgrep`
- `checkov`

#### 9.4.4 `severity`

Mapped into a unified severity model:

| Scanner | Native severity                  | Mapped        |
|---------|----------------------------------|---------------|
| Trivy   | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | same   |
| Semgrep | `ERROR` / `WARNING` / `INFO`     | `high` / `medium` / `info` |
| Checkov | `HIGH` / `MEDIUM` / `LOW`        | same          |

#### 9.4.5 `title`

Short human-readable summary.

Examples:

- “Vulnerable dependency lodash@4.17.15”.
- “Hardcoded credentials in config file”.
- “Kubernetes Pod allows privilege escalation”.

#### 9.4.6 `description`

Structured explanation extracted from scanner output:

- Vulnerability description.
- Rule description.
- CWE details.
- Dependency vulnerability summary.

This field is **not AI-generated**. AI explanations appear separately.

#### 9.4.7 `filePath`, `lineStart`, `lineEnd`

Where applicable (Semgrep, sometimes Checkov).

For Trivy/SCA, `filePath` points to the manifest, for example:

- `package.json`
- `requirements.txt`
- `pom.xml`

#### 9.4.8 `dependency` (SCA-only)

Example:

```json
"dependency": {
  "name": "lodash",
  "version": "4.17.15",
  "ecosystem": "npm",
  "manifestPath": "package.json",
  "dependencyChain": ["myapp", "lodash"]
}
```

#### 9.4.9 `iacResource` (IaC-only)

Example:

```json
"iacResource": {
  "resourceId": "aws_security_group.web",
  "resourceType": "security_group",
  "policyId": "CKV_AWS_123",
  "policyTitle": "Ensure security group does not allow ingress from 0.0.0.0/0"
}
```

#### 9.4.10 `codeSnippet` (SAST)

Extracted from local files for context:

```json
"codeSnippet": {
  "language": "python",
  "content": "password = \"12345\""
}
```

#### 9.4.11 `recommendation`

Initial trivial recommendations extracted from scanner output (non-AI), for example:

- “Upgrade lodash to 4.17.21”.
- “Disable privilege escalation in Pod spec”.

#### 9.4.12 `scannerMetadata`

Raw output preserved, but optionally truncated for size:

```json
"scannerMetadata": {
  "ruleId": "PY.SAST.HARDCODED.PASSWORD",
  "cwe": "CWE-259",
  "cvss": 7.5,
  "references": [ ],
  "rawFinding": { }
}
```

This preserves auditability.

### 9.5 Severity Model

Unified model:

- `critical`
- `high`
- `medium`
- `low`
- `info`

This is consistent across scanners and supports threshold-based CI policies, for example:

```bash
lucidscan --fail-on=high
```

### 9.6 Example Unified Issue (SAST)

```json
{
  "id": "semgrep:PY001:/src/app/handlers.py:42",
  "scanner": "sast",
  "sourceTool": "semgrep",
  "severity": "high",
  "title": "Hardcoded credentials detected",
  "description": "Hardcoded values used for authentication.",
  "filePath": "src/app/handlers.py",
  "lineStart": 42,
  "lineEnd": 42,
  "dependency": null,
  "iacResource": null,
  "codeSnippet": {
    "language": "python",
    "content": "api_key = \"secret123\""
  },
  "recommendation": "Move secrets to environment variables or a vault.",
  "scannerMetadata": {
    "ruleId": "python.hardcoded-credentials",
    "cwe": "CWE-798"
  }
}
```

### 9.7 Example Unified Issue (SCA)

```json
{
  "id": "trivy:lodash:4.17.15:critical",
  "scanner": "sca",
  "sourceTool": "trivy",
  "severity": "critical",
  "title": "Vulnerable dependency lodash@4.17.15",
  "description": "lodash versions <4.17.21 contain prototype pollution vulnerabilities.",
  "filePath": "package.json",
  "dependency": {
    "name": "lodash",
    "version": "4.17.15",
    "ecosystem": "npm",
    "manifestPath": "package.json",
    "dependencyChain": ["myapp", "lodash"]
  },
  "recommendation": "Upgrade to lodash>=4.17.21",
  "scannerMetadata": {
    "cve": "CVE-2021-23337",
    "cvss": 9.8,
    "references": [
      "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
    ]
  }
}
```

### 9.8 Example Unified Issue (IaC)

```json
{
  "id": "checkov:CKV_AWS_23:modules/security/main.tf",
  "scanner": "iac",
  "sourceTool": "checkov",
  "severity": "high",
  "title": "Security Group allows unrestricted ingress",
  "description": "Ensure no security group allows ingress from 0.0.0.0/0.",
  "filePath": "modules/security/main.tf",
  "iacResource": {
    "resourceId": "aws_security_group.web",
    "policyId": "CKV_AWS_23"
  },
  "recommendation": "Restrict ingress to known IP ranges.",
  "scannerMetadata": {}
}
```

### 9.9 Future Extensions to the Schema

Planned extensions:

- `aiExplanation`.
- `fixPatch` (automated patch generation).
- `riskScore` combining CVSS, EPSS, and reachability.
- Evidence nodes for dataflow (future SAST enhancements).

The schema is versioned specifically to allow for backward-compatible growth.


## 10. Packaging & Installation Strategy

`lucidscan` is distributed as a lightweight Python package that delivers the CLI and bootstrap logic, while all heavy scanning tools (Trivy, Semgrep, Checkov) are bundled separately and downloaded automatically on first run. This design provides near-zero installation friction, reproducibility across environments, and excellent performance in both local development and CI environments.

The installation strategy is built around four pillars:

- Simple installation for developers.
- Bundled, version-pinned scanner tools.
- First-run bootstrapping to fetch platform-specific tool bundles.
- Fully self-contained Docker image for CI pipelines.

The goal is to make `lucidscan` trivial to install, consistent across systems, and as fast as possible.

### 10.0 Build Artifacts Overview

The build process produces two types of artifacts:

1. **Python Package (CLI)**: A lightweight pip-installable package containing only the `lucidscan` CLI code, orchestrator, adapters, and bootstrap logic. Published to PyPI.

2. **Platform-Specific Tool Bundles**: Self-contained archives containing a Python virtual environment with Semgrep and Checkov pre-installed, plus the Trivy binary. One bundle is built per supported platform and published to GitHub Releases.

### 10.1 Distribution Channels

`lucidscan` is distributed through two official channels.

#### 10.1.1 PyPI (Python Package Index)

Developers install `lucidscan` via:

```bash
pip install lucidscan
```

The PyPI package contains:

- The `lucidscan` CLI entrypoint.
- Orchestrator, adapters, normalization logic.
- Bootstrap code for downloading scanner bundles.
- Configuration loader.
- Unified schema definitions.

It does **not** contain scanner binaries, keeping the wheel small (target: < 5 MB).

#### 10.1.2 GitHub Releases (Tool Bundles)

Platform-specific tool bundles are published to GitHub Releases:

```text
https://github.com/<org>/lucidscan/releases/download/v{version}/lucidscan-bundle-{platform}-{arch}.tar.gz
```

Example bundle names:

- `lucidscan-bundle-linux-amd64.tar.gz`
- `lucidscan-bundle-linux-arm64.tar.gz`
- `lucidscan-bundle-darwin-arm64.tar.gz`
- `lucidscan-bundle-windows-amd64.zip`

Each release includes:

- All platform bundles.
- Checksums file (`SHA256SUMS`).
- Release notes with scanner versions.

#### 10.1.3 Docker Image (for CI use)

A pre-packaged image is hosted at:

```text
ghcr.io/<org>/lucidscan:latest
```

This image contains:

- `lucidscan` CLI.
- Trivy binary.
- Python 3.11 virtual environment with Semgrep and Checkov pip-installed.
- Pre-warmed Trivy DB (optional).
- Stable directory structure identical to the local environment.

This ensures extremely fast CI execution and avoids `pip` installation overhead.

### 10.2 First-Run Bootstrap Process

After installing via `pip`, the user runs:

```bash
lucidscan --all
```

If the environment is not yet initialized, `lucidscan` performs an automatic bootstrap.

#### 10.2.1 Detect Platform

The bootstrapper identifies:

- Operating system: macOS, Linux, Windows.
- Architecture: `amd64` or `arm64`.

#### 10.2.2 Download Tool Bundle

`lucidscan` downloads a platform-specific tarball or zip file from GitHub Releases:

```text
https://github.com/<org>/lucidscan/releases/download/v{version}/lucidscan-bundle-{platform}-{arch}.tar.gz
```

Each bundle contains:

- `bin/trivy` — Trivy binary for the target platform.
- `venv/` — A complete Python virtual environment with:
  - Semgrep (pip-installed).
  - Checkov (pip-installed).
  - All required Python dependencies.
- `versions.json` — Pinned versions of all bundled tools.

Approximate bundle size: **~150–250 MB compressed** (varies by platform).

#### 10.2.3 Extract to Local Directory

Tools are unpacked into:

```text
~/.lucidscan/
  bin/
    trivy               # Trivy binary
  venv/                 # Python virtual environment
    bin/
      python
      semgrep           # Semgrep CLI (pip-installed)
      checkov           # Checkov CLI (pip-installed)
    lib/python3.11/...  # Python packages
  cache/
    trivy/
  config/
    versions.json
```

#### 10.2.4 Verify Installation

`lucidscan` verifies:

- Trivy binary exists and is executable.
- Virtual environment is intact.
- Semgrep and Checkov are runnable from the venv.
- Expected versions match `versions.json`.
- Directory integrity.

After this, the system is fully operational.

### 10.3 Local Directory Structure

The installation produces:

```text
~/.lucidscan/
  bin/
    trivy                # Trivy binary for the platform
  venv/                  # Self-contained Python 3.11 virtual environment
    bin/
      python             # Python interpreter
      semgrep            # Semgrep CLI entry point
      checkov            # Checkov CLI entry point
    lib/python3.11/
      site-packages/     # All Python dependencies
  cache/
    trivy/db/            # Trivy vulnerability database
  config/
    versions.json        # Pinned tool versions
    user-config.yml      # User configuration overrides
```

All scanners run from this directory rather than the system `PATH`, ensuring consistent tool versions across all users. The bundled venv is completely isolated from the system Python installation.

### 10.4 Version Pinning & Updates

#### 10.4.1 Source of Truth: `pyproject.toml`

The canonical source of truth for scanner versions is the `[tool.lucidscan.scanners]` section in `pyproject.toml`:

```toml
[tool.lucidscan.scanners]
trivy = "0.58.1"
semgrep = "1.102.0"
checkov = "3.2.346"
```

This section:

- **Defines exact versions** of Trivy, Semgrep, and Checkov to bundle.
- **Is version-controlled** with the `lucidscan` source code.
- **Is read by the build process** to create platform bundles.
- **Can be updated via PRs** when scanner versions need to be bumped.
- **Follows Python ecosystem conventions** using the standard `[tool.X]` pattern.

When a new `lucidscan` release is tagged, the build process reads these versions and uses them to:

1. Download the specified Trivy binary.
2. `pip install` the specified Semgrep and Checkov versions into the bundle venv.
3. Generate the bundle's `versions.json` with all version metadata.

#### 10.4.2 Installed Version Information: `versions.json`

After installation, version information is stored locally in:

```text
~/.lucidscan/config/versions.json
```

Example:

```json
{
  "lucidscan": "0.7.0",
  "trivy": "0.58.1",
  "semgrep": "1.102.0",
  "checkov": "3.2.346",
  "python": "3.11",
  "platform": "linux-amd64",
  "bundleVersion": "2025.01.25"
}
```

This file is generated during the build and included in the bundle. It allows:

- The CLI to report exact versions via `lucidscan --version`.
- Scan results to include scanner version metadata.
- Debugging and reproducibility verification.

#### 10.4.3 Update Flow

Users update via `pip`:

```bash
pip install --upgrade lucidscan
```

And optionally refresh tool bundles:

```bash
lucidscan --update-tools
```

On update, only changed scanners are re-downloaded.

### 10.5 No External Dependencies

The Python package does not require:

- System Python versions (beyond the one used to install `lucidscan`).
- System `pip`.
- System Semgrep installation.
- System Checkov installation.
- Docker (for local CLI usage).
- Node / Java / Go / Ruby / other package managers.

Everything required for scanning is bundled.

This eliminates dependency hell and makes installation extremely stable.

### 10.6 Offline / Air-Gapped Support

Once the tool bundle is downloaded, `lucidscan` runs fully offline.

Organizations can:

- Pre-download tool bundles.
- Distribute them internally.
- Configure `lucidscan` to install tools from an internal server mirror via configuration, e.g.:

```yaml
toolBundleUrl: "https://internal-artifacts.mycorp/lucidscan-tools"
```

### 10.7 Cross-Platform Support

`lucidscan` builds and supports the following platform matrix:

| OS             | Arch    | Python | Notes                              |
|----------------|---------|--------|------------------------------------|
| ubuntu-latest  | amd64   | 3.11   | Primary Linux target               |
| ubuntu         | arm64   | 3.11   | Built via QEMU container emulation |
| macos-latest   | arm64   | 3.11   | Supports all modern Apple Silicon Macs |
| windows-latest | amd64   | 3.11   | Windows 10+ users                  |

**Platform Notes:**

- **Linux amd64**: The primary and most tested platform. Used in most CI environments.
- **Linux arm64**: Supports AWS Graviton, Raspberry Pi, and other ARM64 Linux systems. Built using QEMU emulation in GitHub Actions.
- **macOS arm64**: Native Apple Silicon support. Covers M1, M2, M3, and future Apple chips.
- **Windows amd64**: Native Windows support. Bundles Windows-compatible binaries (Trivy `.exe`) and a Windows Python venv.

All platforms use Python 3.11 for the bundled virtual environment to ensure consistency. Semgrep and Checkov are pip-installed into the bundled venv on each platform during the build process.

### 10.8 Build Process & GitHub Actions

The build process is fully automated via GitHub Actions and produces both the Python package and platform-specific tool bundles.

#### 10.8.1 Build Matrix

GitHub Actions runs a matrix build across all supported platforms:

```yaml
strategy:
  matrix:
    include:
      - os: ubuntu-latest
        arch: amd64
        python: "3.11"
        bundle_name: lucidscan-bundle-linux-amd64.tar.gz
      - os: ubuntu-latest
        arch: arm64
        python: "3.11"
        bundle_name: lucidscan-bundle-linux-arm64.tar.gz
        container: arm64v8/python:3.11
      - os: macos-latest
        arch: arm64
        python: "3.11"
        bundle_name: lucidscan-bundle-darwin-arm64.tar.gz
      - os: windows-latest
        arch: amd64
        python: "3.11"
        bundle_name: lucidscan-bundle-windows-amd64.zip
```

#### 10.8.2 Bundle Build Steps

For each platform, the build process:

1. **Read scanner versions from `pyproject.toml`** — Extract pinned versions:
   ```bash
   # Using Python to read the TOML
   TRIVY_VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['lucidscan']['scanners']['trivy'])")
   SEMGREP_VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['lucidscan']['scanners']['semgrep'])")
   CHECKOV_VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['lucidscan']['scanners']['checkov'])")
   ```

2. **Set up Python 3.11** — Install the target Python version.

3. **Create virtual environment** — Create an isolated venv for the bundle:
   ```bash
   python -m venv bundle/venv
   ```

4. **Install Semgrep** — Install the pinned Semgrep version into the venv:
   ```bash
   bundle/venv/bin/pip install semgrep==${SEMGREP_VERSION}
   ```

5. **Install Checkov** — Install the pinned Checkov version into the venv:
   ```bash
   bundle/venv/bin/pip install checkov==${CHECKOV_VERSION}
   ```

6. **Download Trivy binary** — Fetch the pinned Trivy release for the platform:
   ```bash
   # Example for Linux amd64
   curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz | tar xzf - -C bundle/bin trivy
   ```

7. **Generate versions.json** — Record all tool versions from `pyproject.toml`:
   ```json
   {
     "lucidscan": "0.7.0",
     "trivy": "0.58.1",
     "semgrep": "1.102.0",
     "checkov": "3.2.346",
     "python": "3.11",
     "platform": "linux-amd64",
     "bundleVersion": "2025.01.25"
   }
   ```

8. **Package bundle** — Create the distributable archive:
   ```bash
   # Linux/macOS
   tar -czvf lucidscan-bundle-{platform}-{arch}.tar.gz -C bundle .
   
   # Windows
   Compress-Archive -Path bundle/* -DestinationPath lucidscan-bundle-windows-amd64.zip
   ```

#### 10.8.3 Python Package Build

Separately, the CLI package is built and published to PyPI:

```bash
python -m build
twine upload dist/*
```

The PyPI package contains only the `lucidscan` Python code (< 5 MB) and does not include scanner binaries.

#### 10.8.4 Release Process

On tagged releases (e.g., `v0.7.0`):

1. GitHub Actions builds all platform bundles in parallel.
2. Checksums are generated (`SHA256SUMS`).
3. All bundles are uploaded to GitHub Releases.
4. The Python package is published to PyPI.
5. Docker images are built and pushed to GHCR.

Release artifacts:

```text
lucidscan v0.7.0 Release
├── lucidscan-bundle-linux-amd64.tar.gz
├── lucidscan-bundle-linux-arm64.tar.gz
├── lucidscan-bundle-darwin-arm64.tar.gz
├── lucidscan-bundle-windows-amd64.zip
├── SHA256SUMS
└── Release Notes
```

#### 10.8.5 ARM64 Linux Build (QEMU)

The ARM64 Linux build uses QEMU emulation within GitHub Actions:

```yaml
- name: Set up QEMU
  uses: docker/setup-qemu-action@v3
  with:
    platforms: arm64

- name: Build ARM64 bundle
  run: |
    docker run --rm --platform linux/arm64 \
      -v ${{ github.workspace }}:/workspace \
      arm64v8/python:3.11 \
      /workspace/scripts/build-bundle.sh
```

This produces native ARM64 binaries without requiring dedicated ARM64 runners.

### 10.9 Docker Image for CI (Recommended)

CI environments should use the official Docker image:

```yaml
image: ghcr.io/<org>/lucidscan:latest

script:
  - lucidscan --all --format json
```

Benefits:

- Zero installation time.
- Tools already bundled.
- Trivy DB pre-warmed for instant SCA scans.
- Reproducible across CI providers.
- No dependency on `pip` or Python version in CI.
- Identical behavior between CI and local dev.

Image contents:

```text
/usr/local/lucidscan/
  bin/
    trivy                # Trivy binary
  venv/                  # Python 3.11 virtual environment
    bin/
      python
      semgrep            # pip-installed
      checkov            # pip-installed
  cache/
    trivy/db/            # Pre-warmed vulnerability database
  config/
    versions.json
```

Environment variable:

```bash
export LUCIDSCAN_HOME=/usr/local/lucidscan
```

The Docker image is built from the Linux amd64 bundle and includes a pre-downloaded Trivy vulnerability database for instant scanning.

### 10.10 Optional Portable Mode

Users can run `lucidscan` directly from an unpacked tool bundle, bypassing installation into `~/.lucidscan/`.

This is useful for:

- CI debugging.
- Ephemeral environments.
- Security-sensitive environments.

Portable mode is activated via:

```bash
lucidscan --portable
```

### 10.11 Why This Strategy Works

This packaging strategy satisfies all design constraints:

| Requirement                | Achieved by                              |
|---------------------------|-------------------------------------------|
| Zero-setup for developers | `pip install` + bootstrap                 |
| Fast local runs           | Cached tools + local scanning             |
| Fast CI runs              | Official Docker image                     |
| Reproducible scans        | Version pinning + consistent bundles      |
| Cross-platform            | Platform-specific bundles                 |
| No dependency conflicts   | Tools run from isolated directories       |
| Easy updates              | `pip` upgrade + bundle refresh            |
| Offline-capable           | Local cache + mirrored tools              |

This is the simplest and most reliable developer experience possible for a security scanning tool.


## 11. CLI UX & Command Structure

The `lucidscan` CLI is the primary interface through which developers run security scans on their source code, dependencies, Infrastructure-as-Code, and container configurations. It is designed to be:

- **Simple**: one main command (`lucidscan --all`).
- **Fast**: local scanning with cached tools.
- **Uniform**: same commands work in local dev and CI.
- **Predictable**: clear, stable output and exit codes.
- **Scriptable**: machine-readable output for CI.

The CLI is installed via `pip` and runs instantly after bootstrap.

This section defines commands, flags, defaults, and usage patterns.

### 11.1 CLI Principles

- **One-command experience**
  - The default workflow is intentionally minimal:

    ```bash
    lucidscan --all
    ```

- **All scanners optional and configurable**
  - Developers can run specific scanners:
    - SCA only.
    - SAST only.
    - IaC only.

- **Deterministic output**
  - Output formats are stable and versioned.

- **No surprise network calls**
  - Only Trivy DB updates occur unless explicitly disabled.

- **CI-ready**
  - Machine-readable JSON, clean exit codes, optional quiet mode.

- **User-friendly local dev**
  - Colorful terminal output, concise summaries, optional detailed views.

### 11.2 Command Overview

`lucidscan` exposes a single main command with flags:

```bash
lucidscan [OPTIONS]
```

Everything is flag-driven to keep the CLI small and memorable.

**Primary commands & flags**

| Command / Flag               | Description                                              |
|-----------------------------|----------------------------------------------------------|
| `--all`                     | Run all scanners (default behavior).                     |
| `--sca`                     | Run Trivy dependency analysis.                           |
| `--sast`                    | Run Semgrep static analysis.                             |
| `--iac`                     | Run Checkov IaC scanning.                                |
| `--path <dir>`              | Scan a specific directory (default: current directory).  |
| `--format table|json|sarif` | Select output format.                                    |
| `--fail-on <severity>`      | Exit with non-zero code if issues ≥ severity.           |
| `--skip-db-update`          | Skip Trivy DB update for speed / reproducibility.        |
| `--ignore-file <file>`      | Additional ignore file.                                  |
| `--config <file>`           | Load `.lucidscan.yml` from a custom path.                  |
| `--debug`                   | Verbose logs for troubleshooting.                        |
| `--version`                 | Show tool + bundled scanner versions.                    |
| `--update-tools`            | Refresh the local bundled tools.                         |

**Internal maintenance commands** (hidden by default in help):

| Command               | Purpose                                                     |
|-----------------------|-------------------------------------------------------------|
| `lucidscan doctor`      | Diagnose installation, missing tools, corrupted bundles.   |
| `lucidscan cache clean` | Delete cache (Trivy DB, Semgrep cache).                    |
| `lucidscan bundle path` | Print bundle installation path.                             |
### 11.3 Default Behavior

Running:

```bash
lucidscan
```

is equivalent to:

```bash
lucidscan --all --format table
```

Default includes:

- SCA (Trivy).
- SAST (Semgrep).
- IaC (Checkov).

Unless overridden in `.lucidscan.yml`.

The scan directory defaults to the current working directory.

### 11.4 Exit Codes

Exit codes are essential for CI/CD.

| Exit code | Meaning                                                            |
|-----------|--------------------------------------------------------------------|
| `0`       | Scan completed with no issues at or above fail threshold.         |
| `1`       | Issues found at or above the severity threshold set by `--fail-on`. |
| `2`       | Scanner failure (Semgrep/Trivy/Checkov error).                    |
| `3`       | Invalid CLI usage or configuration.                               |
| `4`       | Tool bootstrap failure or missing tool bundle.                    |

CI uses:

```bash
lucidscan --fail-on high
```

to block merging changes that introduce serious vulnerabilities.

### 11.5 Output Formats

#### 11.5.1 `table` (default)

Human-friendly summary:

```text
Scanner  Severity  File/Resource                Description
-------- --------  ---------------------------  -------------------------------
SCA      HIGH      package.json > lodash        Prototype pollution vulnerability
SAST     HIGH      src/utils/auth.py:42         Hardcoded credentials detected
IaC      MEDIUM    aws_security_group.web       0.0.0.0/0 ingress rule
```

#### 11.5.2 `json`

Machine-readable output using the Unified Issue Schema:

```bash
lucidscan --format json > results.json
```

Ideal for CI or integration in tools.

#### 11.5.3 `sarif`

Supports GitHub Advanced Security / Azure DevOps integrations:

```bash
lucidscan --format sarif > results.sarif
```

SARIF output maps fields from UIS to SARIF concepts.

### 11.6 Specifying Scanners

Examples:

- Only dependency scan:

  ```bash
  lucidscan --sca
  ```

- Only SAST scan:

  ```bash
  lucidscan --sast
  ```

- SAST + IaC:

  ```bash
  lucidscan --sast --iac
  ```

If neither `--sca`, `--sast`, nor `--iac` is provided, `--all` is assumed.

### 11.7 Specifying Scan Paths

Default is the current directory.

To scan a subfolder:

```bash
lucidscan --path services/api
```

To scan multiple directories:

```bash
lucidscan --path frontend --path backend
```

Paths are aggregated internally and passed to each scanner.

### 11.8 Configuration Resolution

The CLI loads configuration in this order:

1. CLI flags (highest precedence).
2. `.lucidscan.yml` in project root.
3. Global config in `~/.lucidscan/config/user-config.yml`.
4. Built-in defaults (lowest precedence).

Example `.lucidscan.yml`:

```yaml
sca: true
sast: true
iac: false
failOn: medium
ignore:
  - "tests/"
  - "**/*.md"
semgrep:
  ruleset: "p/ci"
```

### 11.9 Ignore System

`lucidscan` uses combined ignore rules from:

- `.lucidscanignore`.
- `.gitignore` (optional, configurable).
- `.lucidscan.yml` `ignore` section.
- CLI flags (`--ignore-file`).

Ignored paths are excluded consistently for all scanners.

### 11.10 Logging & Verbosity

**Normal mode**

- Concise output.
- No raw scanner logs.

**Debug mode**

```bash
lucidscan --debug
```

Shows:

- Full scanner command invocation.
- Tool paths.
- Version information.
- Environment variables used.
- Raw scanner logs.

Used for troubleshooting or reporting issues.

### 11.11 Examples

- **Typical local run**

  ```bash
  lucidscan --all
  ```

- **CI run blocking failures above medium**

  ```bash
  lucidscan --format json --fail-on medium
  ```

- **Skip Trivy DB update for speed**

  ```bash
  lucidscan --sca --skip-db-update
  ```

- **Generate SARIF for GitHub PR annotations**

  ```bash
  lucidscan --all --format sarif > results.sarif
  ```

### 11.12 CLI Help System

```bash
lucidscan --help
```

Displays:

- Intro.
- Usage.
- Main flags.
- Examples.

```bash
lucidscan --help-all
```

Displays:

- Maintenance commands.
- Expert options.
- Environment variables.

This keeps the default help output simple but powerful.

### 11.13 Design for Future Extensions

The CLI is intentionally flat but extensible.

Future subcommands may include:

```bash
lucidscan sbom
lucidscan ai-explain
lucidscan login   # if SaaS is added later
lucidscan serve   # future server mode
```

But V1 keeps the experience tight and minimalist.


## 12. Configuration System (`.lucidscan.yml`)

`lucidscan` provides a flexible configuration system that allows developers and teams to customize scanning behavior at the project level and globally across machines. The configuration mechanism is inspired by tools like Semgrep, ESLint, and Prettier—designed to be simple, predictable, and overrideable by CLI flags.

Configuration can:

- Enable / disable scanners.
- Control severity thresholds.
- Specify ignore rules.
- Configure Semgrep rulepacks.
- Specify CI behavior.
- Toggle AI explanations.
- Define advanced scanner options.

The CLI loads configuration from three layers, with CLI flags overriding everything.

### 12.1 Configuration Loading Order (Precedence)

Configuration precedence:

1. **CLI flags** (highest priority).
2. **Project-local config**:
   - `<project-root>/.lucidscan.yml`
3. **User-global config**:
   - `~/.lucidscan/config/user-config.yml`
4. **Built-in defaults** (lowest priority).

This ensures:

- Teams can enforce repo settings.
- Users can set personal preferences.
- CLI flags always win (e.g., CI overrides).

### 12.2 Configuration File Format

The configuration file is YAML and supports the following top-level keys:

```yaml
sca: true
sast: true
iac: true

failOn: medium

ignore:
  - "tests/"
  - "*.md"

semgrep:
  ruleset: "p/default"
  additionalRules:
    - "rules/custom-security.yml"

trivy:
  skipDbUpdate: false
  ignoreUnfixed: true

checkov:
  softFail: false
  framework:
    - terraform
    - kubernetes

ai:
  explanations: false

output:
  format: table
```

Every field is optional. `lucidscan` provides sensible defaults.

### 12.3 Core Keys

#### 12.3.1 `sca`, `sast`, `iac`

Boolean values enabling or disabling specific scanners.

Example:

```yaml
sca: true
sast: false
iac: true
```

If none are defined, `--all` is assumed.

#### 12.3.2 `failOn`

Controls exit code severity threshold.

Valid values:

- `critical`
- `high`
- `medium`
- `low`
- `info`
- `none` (always exit 0)

Example:

```yaml
failOn: high
```

Used heavily in CI.

#### 12.3.3 `ignore`

List of file or directory patterns to exclude.

Supports:

- Globs (e.g., `*.md`).
- Directories (e.g., `tests/`).
- Recursive wildcards (e.g., `**/generated/*`).
- Negation rules (e.g., `!src/keep-this.js`).

Example:

```yaml
ignore:
  - "dist/"
  - "**/*.lock"
  - "*.md"
```

These patterns are merged with `.lucidscanignore` (if present).

### 12.4 Semgrep Configuration

Semgrep-specific config is nested under `semgrep`.

#### 12.4.1 `ruleset`

One of:

- Semgrep built-in packs (e.g., `p/security-audit`, `p/r2c`).
- Multiple rulepacks possible.

Example:

```yaml
semgrep:
  ruleset:
    - "p/security-audit"
    - "p/secrets"
```

#### 12.4.2 `additionalRules`

Allows teams to specify project-level rules:

```yaml
semgrep:
  additionalRules:
    - "semgrep/custom/*.yml"
```

#### 12.4.3 `timeout`

Override Semgrep scan timeout:

```yaml
semgrep:
  timeout: 120
```

### 12.5 Trivy Configuration (SCA)

Trivy-specific settings fall under `trivy`.

#### 12.5.1 `skipDbUpdate`

For speed or reproducibility:

```yaml
trivy:
  skipDbUpdate: true
```

#### 12.5.2 `ignoreUnfixed`

Ignore vulnerabilities without fixes:

```yaml
trivy:
  ignoreUnfixed: true
```

#### 12.5.3 `severity`

Filter severity levels:

```yaml
trivy:
  severity:
    - HIGH
    - CRITICAL
```

### 12.6 Checkov Configuration (IaC)

Checkov options live under `checkov`.

#### 12.6.1 `softFail`

Warn instead of failing the pipeline:

```yaml
checkov:
  softFail: true
```

#### 12.6.2 `framework`

Restrict scanning to specific frameworks:

```yaml
checkov:
  framework:
    - terraform
    - kubernetes
```

#### 12.6.3 `skipChecks`

Ignore specific checks:

```yaml
checkov:
  skipChecks:
    - CKV_AWS_23
    - CKV_GCP_19
```

### 12.7 AI Configuration

Although AI explanations are not part of V1 scanning logic, the schema supports a toggle:

```yaml
ai:
  explanations: true
```

Future versions may support:

- Local caching.
- Remote or LLM API inference.
- Severity-aware explanation.

### 12.8 Output Configuration

Control presentation:

```yaml
output:
  format: json     # json | table | sarif
  colors: true
```

Defaults:

- Local: `table`.
- CI: `json`.

### 12.9 Environment Variables

`lucidscan` respects environment variables for scripting, CI, and automation:

| Variable                | Purpose                                   |
|-------------------------|-------------------------------------------|
| `lucidscan_CONFIG`       | Path to config file.                      |
| `lucidscan_HOME`         | Override default `~/.lucidscan` directory.  |
| `lucidscan_DEBUG`        | Enable debug logs.                        |
| `lucidscan_NO_COLOR`     | Disable colored output.                   |
| `lucidscan_SKIP_DB_UPDATE` | Global override for Trivy DB updates.  |

Example:

```bash
lucidscan_SKIP_DB_UPDATE=1 lucidscan --sca
```

### 12.10 Merging Rules

Configuration merging works as follows:

1. Start with built-in defaults.
2. Overlay global config (`~/.lucidscan/config/user-config.yml`).
3. Overlay project config (`.lucidscan.yml`).
4. Override with CLI flags.

This makes the system predictable and transparent.

### 12.11 Configuration Validation

Invalid configuration entries:

- Generate a clear error.
- List the invalid keys.
- Show examples of correct syntax.

Example:

```text
Invalid key 'scann' in .lucidscan.yml
Did you mean 'sca'?
```

This prevents silent misconfiguration.

### 12.12 Minimal Configuration Example

```yaml
sca: true
sast: true
iac: false
failOn: medium

ignore:
  - "tests/"
```

### 12.13 Full Configuration Example

```yaml
sca: true
sast: true
iac: true

failOn: high

ignore:
  - "dist/"
  - "**/*.md"

semgrep:
  ruleset:
    - "p/security-audit"
    - "p/secrets"
  additionalRules:
    - "rules/custom/*.yml"

trivy:
  skipDbUpdate: false
  ignoreUnfixed: true

checkov:
  softFail: false
  framework:
    - terraform
    - kubernetes
  skipChecks:
    - CKV_AWS_23

ai:
  explanations: true

output:
  format: table
  colors: true
```

## 13. CI/CD Integration

`lucidscan` integrates seamlessly with all major CI/CD systems by providing a fully self-contained Docker image that includes:

- `lucidscan` CLI.
- Trivy, Semgrep, Checkov (already installed).
- A pre-warmed Trivy DB (optional, configurable).
- Identical directory structure to local installations.

This ensures CI scans are fast, reproducible, and require zero setup: no `pip` installation, no downloading tools inside pipelines, no Python conflicts, and no long bootstrap times.

Local development uses `pip install` → bootstrap, whereas CI uses the official container image for maximum speed.

### 13.1 Docker Image Overview

The official CI image is published at:

```text
ghcr.io/<org>/lucidscan:latest
```

It contains:

```text
/usr/local/lucidscan/
  bin/
    trivy                # Trivy binary
  venv/                  # Python 3.11 virtual environment
    bin/
      python
      semgrep            # pip-installed
      checkov            # pip-installed
  cache/
    trivy/db/            # Pre-warmed vulnerability database
  config/
    versions.json
```

Environment variable:

```bash
export LUCIDSCAN_HOME=/usr/local/lucidscan
```

This mirrors `~/.lucidscan` on developer machines.

Benefits:

- Instant SCA scans due to pre-warmed DB.
- Consistent behavior between local and CI.
- No Python or `pip` installation required in CI.
- Minimal pipeline runtime.
- Small and predictable CI footprint.

### 13.2 CI Exit Behavior

CI decisions are controlled by:

```bash
lucidscan --fail-on <severity>
```

Severity levels:

- `critical`
- `high`
- `medium`
- `low`
- `info`
- `none` (never fail)

Exit code behavior:

| Exit Code | Explanation                             |
|-----------|-----------------------------------------|
| `0`       | No issues at or above threshold.       |
| `1`       | Issues found at or above threshold.    |
| `2`       | Scanner execution failed.              |
| `3`       | Invalid usage or configuration.        |
| `4`       | Tool bundle problem (not expected in CI). |

Typical usage:

```bash
lucidscan --all --fail-on high --format json
```

### 13.3 CI Output Formats

**Machine-readable JSON**

Recommended for:

- Artifact storage.
- Report ingestion.
- Dashboards.
- Programmatic parsing.

```bash
lucidscan --format json
```

**SARIF**

For GitHub Advanced Security and other SARIF-compatible systems:

```bash
lucidscan --format sarif > results.sarif
```

CI workflows can annotate pull requests automatically.

### 13.4 GitHub Actions Integration

**Simple integration**

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/<org>/lucidscan:latest
    steps:
      - uses: actions/checkout@v4

      - name: Run lucidscan
        run: lucidscan --all --format json --fail-on high
```

**SARIF integration (PR annotations)**

```yaml
- name: Run lucidscan
  run: lucidscan --all --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### 13.5 GitLab CI Integration

```yaml
security_scan:
  image: ghcr.io/<org>/lucidscan:latest
  script:
    - lucidscan --all --format json --fail-on high
  artifacts:
    paths:
      - lucidscan-results.json
    reports:
      dotenv: lucidscan-results.json
```

GitLab can also treat the JSON output as a custom vulnerability report.

### 13.6 Bitbucket Pipelines Integration

```yaml
pipelines:
  default:
    - step:
        name: Security Scan
        image: ghcr.io/<org>/lucidscan:latest
        script:
          - lucidscan --all --format json --fail-on high
```

### 13.7 Jenkins / Generic CI Integration

Docker agent example:

```groovy
pipeline {
  agent {
    docker {
      image 'ghcr.io/<org>/lucidscan:latest'
    }
  }
  stages {
    stage('Scan') {
      steps {
        sh 'lucidscan --all --format json --fail-on high'
        archiveArtifacts artifacts: 'results.json', allowEmptyArchive: true
      }
    }
  }
}
```

### 13.8 Caching Considerations

Because all scanners and DBs are pre-bundled in the Docker image:

- CI pipelines rarely need caching.
- No tool installation is repeated.
- Trivy DB updates occur only at image build time.

If a user wants CI caches anyway:

```yaml
cache:
  key: trivy-db
  paths:
    - /usr/local/lucidscan/cache/trivy/db
```

This is optional.

### 13.9 Monorepo Support

`lucidscan` supports multi-directory scanning:

```yaml
script:
  - lucidscan --path services/api --path services/web --all
```

Or patterns:

```bash
lucidscan --path "services/*" --all
```

You can include multiple job steps or run `lucidscan` in matrix mode in GitHub Actions.

### 13.10 Pull Request Workflow

Recommended PR workflow:

1. Developer pushes feature branch.
2. `lucidscan` runs in CI.
3. If issues ≥ threshold → pipeline fails.
4. SARIF uploaded → GitHub annotates code lines with findings.
5. Developer fixes vulnerabilities.
6. Pipeline passes → PR ready to merge.

This creates a smooth developer security workflow with minimal noise.

### 13.11 Failing the Build on Specific Severity Levels

Examples:

- **Fail on any high/critical issues**

  ```bash
  lucidscan --fail-on high
  ```

- **Fail on medium or above**

  ```bash
  lucidscan --fail-on medium
  ```

- **Don’t fail on anything**

  ```bash
  lucidscan --fail-on none
  ```

This allows security gates to be configured per repo.

### 13.12 CI Time Expectations

- Warm CI image: **1–5 seconds** to run a full scan.
- Without warm DB: **10–20 seconds** for initial run.
- No `pip` installation needed.
- No downloading of tools.
- Extremely predictable and fast.

### 13.13 Recommended CI Patterns

- **Pattern 1 – “Fail early”**
  - Run `lucidscan` as the first job before expensive tests.

- **Pattern 2 – “Security gate before merge”**
  - Only block merging if severity ≥ `high`.

- **Pattern 3 – “Nightly deep scans”**
  - Run `lucidscan --all` on `main` nightly with no thresholds.

- **Pattern 4 – “Allow-listed repos”**
  - Disable scanners selectively via `.lucidscan.yml`.

### 13.14 Future CI Enhancements (Not in V1)

Planned (not implemented in V1):

- Uploading results to a hosted dashboard.
- Incremental scanning (only changed files).
- Agent-based multi-scan orchestration.
- SAST reachability correlation (SAST + SCA).
- GitHub App for automatic PR comments.


## 14. Logging, Error Handling & Telemetry

`lucidscan` is designed to be a developer-first security tool that behaves predictably, communicates clearly, and provides actionable diagnostics. All logging, errors, and telemetry behaviors are explicitly defined to avoid surprise network calls, noisy output, or unpredictable failure modes.

Guiding principles:

- Fail loudly, but fail clearly.
- Debug logs for developers, silent mode for CI.
- Never phone home without user consent.
- Prefer graceful fallbacks instead of hard crashes.
- Clean exit codes suitable for CI pipelines.

This section defines how `lucidscan` logs, reports errors, and optionally emits anonymous telemetry.

### 14.1 Logging Philosophy

- **Minimal output by default**
  - `lucidscan` only prints essential progress indicators and final results.
- **Developer-friendly formatting**
  - Local runs include color, indentation, and concise text.
- **CI-friendly formatting**
  - When using `--format json` or `--format sarif`, logging is suppressed unless `--debug` is provided.
- **Debug mode provides full insight**
  - Raw scanner process output.
  - Internal decisions (ignore patterns, config path).
  - Tool bundle paths.
  - Timings.

No logs are ever sent to external services (unless telemetry is explicitly enabled by the user).

### 14.2 Logging Levels

`lucidscan` defines three logging modes:

#### Normal Mode (default)

- Minimal console text.
- Colored summary table (unless disabled).
- No raw scanner output.
- Error messages visible.
- Ideal for local development.

#### Quiet / CI Mode

Automatically activated when:

- Output format is `json` or `sarif`, or
- Environment is a non-interactive terminal, or
- `lucidscan_CI=1`.

Behavior:

- No progress logs.
- No colored output.
- Only validated JSON/SARIF printed.
- Errors printed to `stderr` in a predictable format.

#### Debug Mode

Enabled via:

```bash
lucidscan --debug
```

or:

```bash
export lucidscan_DEBUG=1
```

Debug mode includes:

- Full scanner command invocation.
- Tool versions and paths.
- Timing for each scanner.
- Config file resolution.
- Ignore rule evaluation.
- Download status for tool bundles.
- System information (OS, architecture).

Used for troubleshooting or filing bug reports.

### 14.3 Error Handling Model

`lucidscan` handles three main types of errors:

- **User errors**.
- **Scanner errors**.
- **System/tooling errors**.

Each category has clear messages and structured reporting.

#### 14.3.1 User Errors

Triggered by:

- Invalid flags.
- Invalid configuration keys.
- Nonexistent paths.
- Missing permissions.

Example:

```text
Error: Unknown option '--alll'. Did you mean '--all'?
Exit code: 3
```

`lucidscan` suggests corrections if possible.

#### 14.3.2 Scanner Errors

Triggered when a scanner (Trivy, Semgrep, Checkov) fails unexpectedly:

- Non-zero exit code from underlying process.
- Missing dependencies inside the bundle.
- Corrupted bundle installation.

Examples:

```text
Scanner error (semgrep): process exited with code 2
Checkov failed: invalid Terraform syntax in modules/security/main.tf
```

`lucidscan` includes relevant `stderr` from scanners in debug mode only.

Exit code: `2`.

#### 14.3.3 Tool Bundle Failures

Issues with bundle installation:

- Corrupted extraction.
- Missing expected files.
- Wrong architecture.
- Checksum mismatch (if enabled).

Example:

```text
lucidscan: Tool bundle integrity check failed.
Try: lucidscan --update-tools
```

Exit code: `4`.

#### 14.3.4 Trivy DB Update Errors

Trivy DB update failures do **not** cause scan failure unless `--require-db-update` is set.

Normal behavior:

- Warn user.
- Continue using cached DB.

Example:

```text
Warning: Unable to update Trivy DB. Using cached DB instead.
```

#### 14.3.5 Graceful Handling of Partial Failures

If one scanner fails but others succeed, `lucidscan`:

- Reports failure in the summary.
- Includes partial results.
- Outputs metadata showing failed scanners.

Example:

```text
Warning: Semgrep failed, but SCA and IaC scans completed.
```

Whether this fails CI depends on the user’s `--fail-on` threshold.

### 14.4 Error Messages Format

All errors follow a consistent structure:

```text
Error: <short message>

Details:
- <specific reason>
- <path or rule>
- <suggested remediation>

Run with --debug for more details.
```

This avoids cryptic scanner-native errors.

### 14.5 Telemetry (Optional & Disabled by Default)

`lucidscan` values privacy. No telemetry is collected by default.

If enabled manually by the user, telemetry:

- Is 100% anonymous.
- Contains no file paths, code, or dependency names.
- Includes only:
  - `lucidscan` version.
  - Scanner versions.
  - Which scanners were enabled.
  - Runtime duration.
  - Error type (if any).

Enable:

```bash
lucidscan --enable-telemetry
```

Disable:

```bash
lucidscan --disable-telemetry
```

or:

```bash
export lucidscan_TELEMETRY_DISABLED=1
```

All telemetry fields are documented in transparent detail.

### 14.6 Logging Locations

- All logs go to `stdout` or `stderr` by default.
- Optionally, users may configure:

  ```text
  ~/.lucidscan/config/logging.yml
  ```

  to persist logs or write them to a file for debugging.

No logs are ever written silently.

### 14.7 Crash Safety & Recovery

`lucidscan` includes several guardrails to avoid leaving the system in a bad state:

- Temporary directories cleaned on failure.
- Trivy DB corruption autocorrected by forcing re-download.
- Bundled venv rebuilt if inconsistency detected.
- Bundle reinstallation triggered automatically if binaries are missing.

In worst-case scenarios, `lucidscan` suggests:

```bash
lucidscan --update-tools
```

or deleting the `~/.lucidscan` directory.

### 14.8 Summary of Guarantees

`lucidscan` guarantees that:

- Scans never silently fail.
- Errors never produce malformed output.
- CI always receives a non-zero exit code on failure.
- Local errors are easy to diagnose.
- Scanner-specific issues are isolated from overall logic.
- Telemetry is off unless explicitly enabled.

This provides a high level of trust and predictability in development and CI workflows.


## 15. AI Explanation Module

The AI Explanation Module enhances lucidscan's findings by generating clear, actionable, context-aware guidance for developers. It transforms raw scanner results into high-quality narrative explanations that help developers understand what the issue means, why it matters, and how to fix it.

AI explanations are an optional feature. The core security scanning remains fully functional without AI, ensuring lucidscan is 100% open source, privacy-preserving, and fully local by default.

### 15.1 Goals

The AI module aims to:

- Provide human-readable descriptions of problems.
- Offer actionable remediation steps with examples.
- Reduce developer time spent interpreting findings.
- Improve onboarding for junior engineers.
- Provide value as a paid feature without limiting open-source functionality.

AI enhancements sit on top of the Unified Issue Schema (Section 9).

### 15.2 Non-Goals

AI does **not**:

- Alter scanner outputs.
- Automatically apply fixes (future feature).
- Upload any code without explicit permission.
- Operate silently in the background.

AI is always explicitly triggered.

### 15.3 Invocation Methods

AI explanations can be invoked in three ways:

#### 15.3.1 Command-line flag

```bash
lucidscan --all --ai
```

or:

```bash
lucidscan --format json --ai
```

#### 15.3.2 Per-issue explanation

```bash
lucidscan explain <issue-id>
```

#### 15.3.3 Post-processing on result files

```bash
lucidscan explain --input results.json --output explained.json
```

This enables offline re-analysis.

### 15.4 Output Format

Each issue gains an additional field:

```json
"aiExplanation": {
  "short": "This hardcoded credential can be extracted by attackers...",
  "long": "Hardcoded credentials are dangerous because...",
  "fixExample": "For example, you can move the secret to an environment variable...",
  "riskScore": 0.82
}
```

If AI is disabled or not configured, this field is `null` or omitted.

### 15.5 Security & Privacy Model

Fundamental rule:

> No source code or sensitive data is ever sent to an AI provider unless the user explicitly configures API keys and approves usage.

By default:

- AI is disabled.
- No network calls happen.
- No external API is invoked.

When enabled, users select a provider:

- Anthropic.
- OpenAI.
- Local LLM (e.g., Ollama).
- A future `lucidscan` SaaS server.

Control is via config:

```yaml
ai:
  explanations: true
  provider: "openai"
  apiKey: "env:OPENAI_API_KEY"
  model: "gpt-4.1"
```

### 15.6 Context Passed to the LLM

`lucidscan` prepares a minimal, privacy-conscious prompt containing:

Always included:

- Issue title.
- Issue description.
- Severity.
- Scanner name (SAST, SCA, IaC).
- Dependency name/version (for SCA).
- IaC resource IDs (for Checkov).

Code snippet is **only** included if the user enables snippet sending.

Snippets require explicit opt-in:

```yaml
ai:
  sendCodeSnippets: true
```

Default: `false`. This protects sensitive codebases.

### 15.7 Prompt Design

Example prompt template:

```text
You are a security expert. Given the following vulnerability data from a security scanner,
generate a clear explanation and actionable remediation steps.

Issue:
- Title: {{title}}
- Severity: {{severity}}
- Description: {{description}}
- File: {{filePath}}:{{lineStart}}
- Code Snippet (optional): {{snippet}}

Write:
1. A short summary
2. Why this issue matters
3. The exact steps to fix it
4. A concrete fix example
5. Additional context for developers
```

Prompt templates are versioned and can be updated independently of scanner logic.

### 15.8 Caching & Performance

AI explanations may be slow (1–5 seconds per issue). `lucidscan` provides:

1. **Per-issue caching**

   Cached at:

   ```text
   ~/.lucidscan/cache/ai/<issue-id>.json
   ```

   AI is only re-run when:

   - Issue content changes.
   - Scanner version changes.
   - User clears cache.

2. **Batch requests**

   For JSON output, `lucidscan` can send multiple issues in a single API call (if the provider supports it).

### 15.9 CI Behavior

- CI **never** runs AI explanations by default.

To enable:

```bash
lucidscan --all --ai --format json
```

Use cases:

- Security audits.
- Developer training.
- Nightly reports.

Not recommended for blocking builds.  
AI explanations **never** affect exit codes.

### 15.10 Premium / Monetization Strategy (Optional)

AI explanations are an ideal paid feature while keeping `lucidscan`’s core open source.

Possible monetization tiers:

- **Free Tier**
  - Scanning only.
  - No AI.

- **Pro (Developer License)**
  - Limited AI calls per month.
  - Up to N issues explained (e.g., 100).

- **Team / Enterprise**
  - Unlimited AI calls.
  - Custom prompts.
  - Self-hosted AI inference server.
  - Audit logs.
  - Central configuration.

- **Enterprise Offline**
  - Local LLM support (e.g., via Ollama).
  - Model hosting on-prem.

Scanning capabilities are **never** gated behind paywalls.

### 15.11 Risks & Mitigations

| Risk                             | Mitigation                                      |
|----------------------------------|-------------------------------------------------|
| Users afraid of sending code     | Code not sent unless opted-in explicitly.       |
| High LLM cost                    | Caching + batch mode.                           |
| Low-quality responses            | Curated prompts + feedback loop.                |
| LLM hallucinations               | Present clear disclaimer; avoid auto-fixes.     |
| Vendor lock-in                   | Pluggable provider architecture.                |
### 15.12 Internal Architecture

The AI module consists of:

- **Issue Normalizer**
  - Converts UIS issues into AI prompt-ready inputs.
- **Provider Adapter**
  - `openai` (HTTP).
  - `anthropic`.
  - Local LLM (Ollama subprocess).
  - Placeholder for future SaaS backend.
- **Prompt Composer**
  - Templates per issue type (SAST, SCA, IaC).
- **Response Parser**
  - Converts LLM output into structured fields.
- **Cache Manager**
  - Stores explanations keyed by issue ID + scanner version.
- **Output Merger**
  - Injects explanations into the final result.

All are local components inside the Python CLI.

### 15.13 Example Final Output (Human Format)

```text
Issue: Hardcoded credentials detected
Severity: High
Location: src/auth/login.py:27

AI Explanation:
  Hardcoded credentials pose a severe security risk because anyone with access
  to the source code can extract them. Attackers may use them to impersonate
  users or escalate privileges.

  Fix:
    - Move the credential to an environment variable.
    - Use a configuration manager or secrets vault.
    - Rotate the exposed secret.

  Example:
    Replace:
      password = "12345"
    With:
      password = os.environ["APP_PASSWORD"]
```

### 15.14 Example Final Output (JSON)

```json
{
  "id": "semgrep:PY001:/src/auth/login.py:27",
  "scanner": "sast",
  "severity": "high",
  "title": "Hardcoded credentials",
  "aiExplanation": {
    "short": "Hardcoded credentials allow attackers to extract passwords directly from the code.",
    "long": "Embedding credentials in source code exposes them to anyone who has access to the repository...",
    "fixExample": "Use environment variables or a secrets manager...",
    "riskScore": 0.89
  }
}
```

## 16. Future Extensions (Roadmap)

lucidscan is intentionally designed with a modular architecture that can evolve well beyond the initial CLI release. The following roadmap outlines future capabilities that build on the foundation of the thick CLI, bundled scanners, unified issue schema, and optional AI explanations.

These items are not part of V1 but represent logical, high-impact directions for the project.

### 16.1 Short-Term Enhancements (1–3 Months After Launch)

#### 16.1.1 Incremental Scanning

Improve performance by scanning only changed files rather than the entire directory.

**Approach:**

- Detect git diff changes.
- Skip unchanged Semgrep targets.
- Skip unmodified IaC files.
- Allow an `--incremental` flag.

This yields a huge speed win for monorepos.

#### 16.1.2 SBOM Generation

Using Trivy or Syft:

```bash
lucidscan sbom --format cyclonedx
```

Useful for compliance (SLSA, ISO 27001, SOC2).

#### 16.1.3 Enhanced Fix Suggestions (Non-AI)

Improve static remediation recommendations extracted from scanners.

**Examples:**

- Automatic “Upgrade to X version” SCA fixes.
- IaC policy examples.
- SAST inline secure coding patterns.

#### 16.1.4 Policy-as-Code Plugin (Minimal Version)

A lightweight rule definition system for:

- Allowed severity levels.
- Forbidden dependencies.
- Required IaC checks.

Managed through `.lucidscan-policy.yml`.

### 16.2 Medium-Term Features (3–9 Months)
#### 16.2.1 IDE Integrations (VS Code, JetBrains)

Provide:

- Inline SAST findings.
- Hover explanations.
- Quick-fix suggestions.
- Rule suppression features.
- Integration with local `lucidscan` bundle.

Mechanism:

- IDE plugin calls `lucidscan` locally.
- No server required.
- Performance optimized via incremental scanning.

This creates a developer workflow similar to SonarLint or Snyk Code, but fully local.

#### 16.2.2 Dashboard / Web UI (Optional)

A local or server-hosted dashboard to:

- Import JSON scan results.
- Compare runs over time.
- Visualize dependency vulnerabilities.
- Perform team-level reporting.

Modes:

- Local UI (Electron or minimal web server).
- Enterprise mode: multi-user dashboard.

This can be an entry point into a future SaaS.

#### 16.2.3 SARIF Rule Mapping Improvements

Better integration with:

- GitHub Advanced Security.
- Azure DevOps.
- SonarQube (via SARIF import).

This increases compatibility with enterprise pipelines.

#### 16.2.4 Plugin System for Custom Scanners

Users can hook in additional scanners:

```bash
lucidscan plugin install bandit
```

Or define custom adapters:

```yaml
plugins:
  - name: my-corp-custom-checks
    command: ./scripts/check-security.sh
```

#### 16.2.5 Secrets Scanning

Add optional integration with:

- Trivy secrets scanner.
- Gitleaks.
- Semgrep secrets rules.

Future CLI flag:

```bash
lucidscan --secrets
```

#### 16.2.6 Auto-Fix Mode (Non-AI or AI-Assisted)

Two versions:

- **Non-AI**: apply known dependency upgrades automatically.
- **AI-assisted**: propose git diffs for SAST or IaC fixes.

Delivered via:

```bash
lucidscan fix <issue-id>
lucidscan fix --all
```

AI-assisted auto-fix can become a premium offering.

### 16.3 Long-Term Extensions (9–24 Months)
#### 16.3.1 Hosted SaaS (Optional Product Line)

A centralized hosted version that supports:

- Team dashboards.
- Policy enforcement.
- Historical scan tracking.
- Multi-repo aggregation.
- Compliance reporting.
- Integration with GitHub/GitLab apps.

Architecture:

- Thin CLI sends results, not code.
- Core scanning remains local to maintain privacy.
- Only metadata leaves the machine.

This keeps the privacy-first promise intact.

#### 16.3.2 Full “Server Mode” for Large Enterprises

Self-hosted on-prem server for:

- Centralized configuration.
- Centralized AI inference.
- Aggregated metrics.
- Rule synchronization.
- Caching and artifacts store.

Thick CLI remains available; server mode becomes optional.

#### 16.3.3 Agent-Based Scanning (Distributed)

Ideal for monorepos:

- Break projects into submodules.
- Scan concurrently across agents.
- Aggregate results.

#### 16.3.4 Reachability Analysis (Advanced SAST + SCA Correlation)

Correlate Semgrep findings with dependency vulnerabilities to reduce noise.

Example:

> “This vulnerable dependency is only reachable through code path X.”

This dramatically reduces false positives and can become a premium differentiator.

#### 16.3.5 ML-Based Issue Ranking (Local or SaaS)

Use local ML models or remote inference to compute:

- Exploit likelihood.
- Contextual severity.
- Prioritization scores.

Expose via a `riskScore` field in the Unified Issue Schema.

#### 16.3.6 Enterprise Knowledge Graph (Future SaaS/Enterprise Feature)

Aggregate organization-wide:

- Dependencies.
- IaC resources.
- Code patterns.
- Known vulnerabilities.

Enable organization-wide analysis and advisories.

### 16.4 Vision Summary

`lucidscan` begins as:

- A fast.
- Local.
- Privacy-first.
- Open source.
- Developer-friendly CLI scanner.

The roadmap positions `lucidscan` to evolve into:

- A full security platform.
- With optional AI augmentation.
- Optional SaaS backend.
- Enterprise features.
- Wide integration with development ecosystems.

All without compromising its local-first foundation.