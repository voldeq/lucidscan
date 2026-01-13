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
from lucidscan.config.loader import find_project_config
from lucidscan.config.validation import (
    ConfigValidationIssue,
    validate_config_file,
    ValidationSeverity,
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
        # Determine config path
        config_path = getattr(args, "config", None)
        if config_path:
            config_path = Path(config_path)
        else:
            # Find in current directory
            config_path = find_project_config(Path.cwd())

        if config_path is None:
            print("No configuration file found.")
            print("Looked for: .lucidscan.yml, .lucidscan.yaml, lucidscan.yml, lucidscan.yaml")
            return EXIT_INVALID_USAGE

        if not config_path.exists():
            print(f"Configuration file not found: {config_path}")
            return EXIT_INVALID_USAGE

        print(f"Validating {config_path}...")

        is_valid, issues = validate_config_file(config_path)

        if not issues:
            print("Configuration is valid.")
            return EXIT_SUCCESS

        # Group by severity
        errors = [i for i in issues if i.severity == ValidationSeverity.ERROR]
        warnings = [i for i in issues if i.severity == ValidationSeverity.WARNING]

        # Print errors
        if errors:
            print(f"\nErrors ({len(errors)}):")
            for issue in errors:
                self._print_issue(issue)

        # Print warnings
        if warnings:
            print(f"\nWarnings ({len(warnings)}):")
            for issue in warnings:
                self._print_issue(issue)

        if errors:
            print(f"\nConfiguration is invalid ({len(errors)} error(s)).")
            return EXIT_ISSUES_FOUND
        else:
            print(f"\nConfiguration is valid with {len(warnings)} warning(s).")
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
