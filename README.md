## lucidscan

`lucidscan` is the CLI component of LucidShark, a unified security scanner that
orchestrates multiple open-source tools (Trivy, Semgrep, Checkov) and exposes a
consistent command-line interface and unified issue schema.

At this stage of development, the CLI is a **skeleton only**. It provides:

- A `lucidscan` executable installed via `pip install -e .`.
- `lucidscan --help` with core global flags.
- Stub scanner flags (`--sca`, `--container`, `--iac`, `--sast`, `--all`) that
  are not yet wired to real scanners.

Refer to the docs in `docs/` for the full product specification and development
plan.


