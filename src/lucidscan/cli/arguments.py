"""Argument parser construction for lucidscan CLI.

This module builds the argument parser with subcommands:
- lucidscan init   - Initialize project configuration
- lucidscan scan   - Run security/quality scans
- lucidscan status - Show configuration and tool status
"""

from __future__ import annotations

import argparse
from pathlib import Path


def _add_global_options(parser: argparse.ArgumentParser) -> None:
    """Add global options available to all commands."""
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show lucidscan version and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (info-level) logging.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Reduce logging output to errors only.",
    )


def _build_init_parser(subparsers: argparse._SubParsersAction) -> None:
    """Build the 'init' subcommand parser."""
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize LucidScan for the current project.",
        description=(
            "Analyze your codebase, detect languages and frameworks, "
            "and generate lucidscan.yml configuration."
        ),
    )
    init_parser.add_argument(
        "--ci",
        choices=["github", "gitlab", "bitbucket"],
        help="Generate CI configuration for the specified platform.",
    )
    init_parser.add_argument(
        "--non-interactive", "-y",
        action="store_true",
        help="Use defaults without prompting (non-interactive mode).",
    )
    init_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Overwrite existing configuration files.",
    )
    init_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to initialize (default: current directory).",
    )


def _build_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    """Build the 'scan' subcommand parser."""
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run the quality/security pipeline.",
        description=(
            "Execute configured scanners and linters. "
            "Results are output in the specified format."
        ),
    )

    # Domain selection
    domain_group = scan_parser.add_argument_group("scan domains")
    domain_group.add_argument(
        "--sca",
        action="store_true",
        help="Scan dependencies for known vulnerabilities (uses Trivy).",
    )
    domain_group.add_argument(
        "--container",
        action="store_true",
        help="Scan container images for vulnerabilities. Use with --image.",
    )
    domain_group.add_argument(
        "--iac",
        action="store_true",
        help="Scan Infrastructure-as-Code (Terraform, K8s, CloudFormation).",
    )
    domain_group.add_argument(
        "--sast",
        action="store_true",
        help="Static application security testing (code pattern analysis).",
    )
    domain_group.add_argument(
        "--lint",
        action="store_true",
        help="Run linting checks (Ruff for Python, ESLint for JS/TS).",
    )
    domain_group.add_argument(
        "--all",
        action="store_true",
        help="Enable all scanner types (SCA, SAST, IaC, Container, Lint).",
    )

    # Target options
    target_group = scan_parser.add_argument_group("targets")
    target_group.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory).",
    )
    target_group.add_argument(
        "--image",
        action="append",
        dest="images",
        metavar="IMAGE",
        help="Container image to scan (can be specified multiple times).",
    )

    # Output options
    output_group = scan_parser.add_argument_group("output")
    output_group.add_argument(
        "--format",
        choices=["json", "table", "sarif", "summary"],
        default=None,
        help="Output format (default: json, or as specified in config file).",
    )

    # Configuration options
    config_group = scan_parser.add_argument_group("configuration")
    config_group.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with code 1 if issues at or above this severity are found.",
    )
    config_group.add_argument(
        "--config",
        metavar="PATH",
        type=Path,
        help="Path to config file (default: .lucidscan.yml in project root).",
    )

    # Execution options
    exec_group = scan_parser.add_argument_group("execution")
    exec_group.add_argument(
        "--sequential",
        action="store_true",
        help="Disable parallel scanner execution (for debugging).",
    )
    exec_group.add_argument(
        "--fix",
        action="store_true",
        help="Apply auto-fixes where possible (linting only).",
    )

    # Enrichment options
    enrich_group = scan_parser.add_argument_group("enrichment")
    enrich_group.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI-powered explanations for issues (requires API key).",
    )


def _build_status_parser(subparsers: argparse._SubParsersAction) -> None:
    """Build the 'status' subcommand parser."""
    status_parser = subparsers.add_parser(
        "status",
        help="Show configuration and tool status.",
        description=(
            "Display lucidscan version, platform info, installed tools, "
            "and scanner plugin status."
        ),
    )
    status_parser.add_argument(
        "--tools",
        action="store_true",
        help="Show detailed installed tool versions.",
    )
    status_parser.add_argument(
        "--config",
        action="store_true",
        dest="show_config",
        help="Show effective configuration.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for lucidscan CLI.

    Returns:
        Configured ArgumentParser instance with subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="lucidscan",
        description="LucidScan - The trust layer for AI-assisted development.",
        epilog=(
            "Examples:\n"
            "  lucidscan init                    # Initialize project\n"
            "  lucidscan init --ci github        # Initialize with GitHub Actions\n"
            "  lucidscan scan --sca              # Scan dependencies\n"
            "  lucidscan scan --all              # Run all scans\n"
            "  lucidscan scan --lint --fix       # Lint and auto-fix\n"
            "  lucidscan status                  # Show tool status\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    _add_global_options(parser)

    # Create subcommands
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands:",
        metavar="COMMAND",
    )

    _build_init_parser(subparsers)
    _build_scan_parser(subparsers)
    _build_status_parser(subparsers)

    return parser
