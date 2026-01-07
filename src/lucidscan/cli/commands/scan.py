"""Scan command implementation."""

from __future__ import annotations

import sys
from argparse import Namespace
from pathlib import Path
from typing import List, Optional

from lucidscan.cli.commands import Command
from lucidscan.cli.config_bridge import ConfigBridge
from lucidscan.cli.exit_codes import (
    EXIT_ISSUES_FOUND,
    EXIT_SCANNER_ERROR,
    EXIT_SUCCESS,
)
from lucidscan.config.ignore import load_ignore_patterns
from lucidscan.config.models import LucidScanConfig
from lucidscan.core.logging import get_logger
from lucidscan.core.models import ScanContext, ScanResult, UnifiedIssue
from lucidscan.pipeline import PipelineConfig, PipelineExecutor
from lucidscan.plugins.reporters import get_reporter_plugin

LOGGER = get_logger(__name__)


class ScanCommand(Command):
    """Executes security scanning."""

    def __init__(self, version: str):
        """Initialize ScanCommand.

        Args:
            version: Current lucidscan version string.
        """
        self._version = version

    @property
    def name(self) -> str:
        """Command identifier."""
        return "scan"

    def execute(self, args: Namespace, config: LucidScanConfig) -> int:
        """Execute the scan command.

        Args:
            args: Parsed command-line arguments.
            config: Loaded configuration.

        Returns:
            Exit code based on scan results.
        """
        try:
            result = self._run_scan(args, config)

            # Determine output format: CLI > config > default (json)
            if args.format:
                output_format = args.format
            elif config.output.format:
                output_format = config.output.format
            else:
                output_format = "json"

            reporter = get_reporter_plugin(output_format)
            if not reporter:
                LOGGER.error(f"Reporter plugin '{output_format}' not found")
                return EXIT_SCANNER_ERROR

            # Write output to stdout
            reporter.report(result, sys.stdout)

            # Check severity threshold - CLI overrides config
            threshold = args.fail_on if args.fail_on else config.fail_on
            if self._check_severity_threshold(result, threshold):
                return EXIT_ISSUES_FOUND

            return EXIT_SUCCESS

        except FileNotFoundError as e:
            LOGGER.error(str(e))
            raise
        except Exception as e:
            LOGGER.error(f"Scan failed: {e}")
            raise

    def _run_scan(
        self, args: Namespace, config: LucidScanConfig
    ) -> ScanResult:
        """Execute the scan based on CLI arguments and config.

        Uses PipelineExecutor to run the scan pipeline:
        1. Linting (if --lint or --all)
        2. Scanner execution (parallel by default)
        3. Enricher execution (sequential, in configured order)
        4. Result aggregation

        Args:
            args: Parsed CLI arguments.
            config: Loaded configuration.

        Returns:
            ScanResult containing all issues found.
        """
        project_root = Path(args.path).resolve()

        if not project_root.exists():
            raise FileNotFoundError(f"Path does not exist: {project_root}")

        enabled_domains = ConfigBridge.get_enabled_domains(config, args)

        # Load ignore patterns from .lucidscanignore and config
        ignore_patterns = load_ignore_patterns(project_root, config.ignore)

        # Build scan context
        context = ScanContext(
            project_root=project_root,
            paths=[project_root],
            enabled_domains=enabled_domains,
            config=config,
            ignore_patterns=ignore_patterns,
        )

        all_issues: List[UnifiedIssue] = []

        # Run linting if requested
        lint_enabled = getattr(args, "lint", False) or getattr(args, "all", False)
        fix_enabled = getattr(args, "fix", False)

        if lint_enabled:
            lint_issues = self._run_linting(context, fix_enabled)
            all_issues.extend(lint_issues)

        # Run security scanning if any domains are enabled
        if enabled_domains:
            # Collect unique scanners needed based on config
            needed_scanners: List[str] = []
            for domain in enabled_domains:
                scanner_name = config.get_plugin_for_domain(domain.value)
                if scanner_name and scanner_name not in needed_scanners:
                    needed_scanners.append(scanner_name)
                elif not scanner_name:
                    LOGGER.warning(
                        f"No scanner plugin configured for domain: {domain.value}"
                    )

            if needed_scanners:
                # Build pipeline configuration
                pipeline_config = PipelineConfig(
                    sequential_scanners=getattr(args, "sequential", False),
                    max_workers=config.pipeline.max_workers,
                    enricher_order=config.pipeline.enrichers,
                )

                # Execute pipeline
                executor = PipelineExecutor(
                    config=config,
                    pipeline_config=pipeline_config,
                    lucidscan_version=self._version,
                )

                scan_result = executor.execute(needed_scanners, context)
                all_issues.extend(scan_result.issues)

        # Build final result
        result = ScanResult(issues=all_issues)
        result.summary = result.compute_summary()

        return result

    def _run_linting(
        self, context: ScanContext, fix: bool = False
    ) -> List[UnifiedIssue]:
        """Run linting checks.

        Args:
            context: Scan context.
            fix: If True, apply automatic fixes.

        Returns:
            List of linting issues.
        """
        from lucidscan.plugins.linters import discover_linter_plugins

        issues: List[UnifiedIssue] = []

        # Discover and run linter plugins
        linter_plugins = discover_linter_plugins()

        if not linter_plugins:
            LOGGER.warning("No linter plugins found")
            return issues

        for name, plugin_class in linter_plugins.items():
            try:
                LOGGER.info(f"Running linter: {name}")
                plugin = plugin_class(project_root=context.project_root)

                if fix and plugin.supports_fix:
                    # Run fix mode
                    fix_result = plugin.fix(context)
                    LOGGER.info(
                        f"{name}: Fixed {fix_result.issues_fixed} issues, "
                        f"{fix_result.issues_remaining} remaining"
                    )
                    # Run again to get remaining issues
                    issues.extend(plugin.lint(context))
                else:
                    issues.extend(plugin.lint(context))

            except Exception as e:
                LOGGER.error(f"Linter {name} failed: {e}")

        return issues

    def _check_severity_threshold(
        self, result: ScanResult, threshold: Optional[str]
    ) -> bool:
        """Check if any issues meet or exceed the severity threshold.

        Args:
            result: Scan result to check.
            threshold: Severity threshold ('critical', 'high', 'medium', 'low').

        Returns:
            True if issues at or above threshold exist, False otherwise.
        """
        if not threshold or not result.issues:
            return False

        threshold_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }

        threshold_level = threshold_order.get(threshold.lower(), 99)

        for issue in result.issues:
            issue_level = threshold_order.get(issue.severity.value, 99)
            if issue_level <= threshold_level:
                return True

        return False
