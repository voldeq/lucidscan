"""Validate command implementation.

Validates lucidscan.yml configuration files and reports issues.
"""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lucidscan.config.models import LucidScanConfig

from lucidscan.cli.commands import Command
from lucidscan.cli.exit_codes import EXIT_ISSUES_FOUND, EXIT_INVALID_USAGE, EXIT_SUCCESS
from lucidscan.config.validation import (
    ConfigValidationIssue,
    validate_config_at_path,
)


class ValidateCommand(Command):
    """Validates lucidscan.yml configuration files."""

    @property
    def name(self) -> str:
        """Command identifier."""
        return "validate"

    def execute(self, args: Namespace, config: "LucidScanConfig | None" = None) -> int:
        """Execute the validate command.

        Validates a configuration file and reports errors/warnings.

        Args:
            args: Parsed command-line arguments.
            config: Optional LucidScan configuration (unused).

        Returns:
            Exit code: 0 = valid, 1 = has errors, 3 = file not found.
        """
        config_path_arg = getattr(args, "config", None)
        result = validate_config_at_path(Path.cwd(), config_path_arg)

        if result.error_message:
            print(result.error_message)
            if result.config_path is None:
                print("Looked for: .lucidscan.yml, .lucidscan.yaml, lucidscan.yml, lucidscan.yaml")
            return EXIT_INVALID_USAGE

        print(f"Validating {result.config_path}...")

        if not result.errors and not result.warnings:
            print("Configuration is valid.")
            return EXIT_SUCCESS

        # Print errors
        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for issue in result.errors:
                self._print_issue(issue)

        # Print warnings
        if result.warnings:
            print(f"\nWarnings ({len(result.warnings)}):")
            for issue in result.warnings:
                self._print_issue(issue)

        if result.errors:
            print(f"\nConfiguration is invalid ({len(result.errors)} error(s)).")
            return EXIT_ISSUES_FOUND
        else:
            print(f"\nConfiguration is valid with {len(result.warnings)} warning(s).")
            return EXIT_SUCCESS

    def _print_issue(self, issue: ConfigValidationIssue) -> None:
        """Print a formatted issue.

        Args:
            issue: The validation issue to print.
        """
        location = ""
        if issue.key:
            location = f" [{issue.key}]"

        print(f"  - {issue.message}{location}")
        if issue.suggestion:
            print(f"    Did you mean '{issue.suggestion}'?")
