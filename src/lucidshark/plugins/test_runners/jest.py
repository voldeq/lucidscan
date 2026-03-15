"""Jest test runner plugin.

Jest is a delightful JavaScript Testing Framework.
https://jestjs.io/
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.plugins.test_runners.base import TestRunnerPlugin, TestResult
from lucidshark.plugins.utils import ensure_node_binary

LOGGER = get_logger(__name__)


class JestRunner(TestRunnerPlugin):
    """Jest test runner plugin for JavaScript/TypeScript test execution."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize JestRunner.

        Args:
            project_root: Optional project root for finding Jest installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "jest"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["javascript", "typescript"]

    def ensure_binary(self) -> Path:
        """Ensure Jest is available."""
        return ensure_node_binary(
            self._project_root,
            "jest",
            "Jest is not installed. Install it with:\n"
            "  npm install jest --save-dev\n"
            "  OR\n"
            "  npm install -g jest",
        )

    def run_tests(self, context: ScanContext) -> TestResult:
        """Run Jest on the specified paths.

        Always runs with --coverage to generate coverage data.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            TestResult with test statistics and issues for failures.
        """
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return TestResult()

        with tempfile.TemporaryDirectory() as tmpdir:
            report_file = Path(tmpdir) / "jest-results.json"

            cmd = [
                str(binary),
                "--json",
                f"--outputFile={report_file}",
                "--passWithNoTests",  # Don't fail if no tests found
                "--coverage",  # Always generate coverage data
            ]

            if context.paths:
                paths = [str(p) for p in context.paths]
                cmd.extend(paths)

            LOGGER.debug(f"Running: {' '.join(cmd)}")

            result = self._run_test_subprocess(cmd, context)
            if result is None:
                return TestResult()

            if report_file.exists():
                return self._parse_json_report(report_file, context.project_root)

            # Check for compilation errors (e.g. ts-jest failing to compile TypeScript)
            if result.returncode != 0 and result.stderr:
                compilation_result = self._check_compilation_errors(
                    result.stderr, context.project_root
                )
                if compilation_result is not None:
                    return compilation_result

            return self._parse_json_output(result.stdout, context.project_root)

    def _check_compilation_errors(
        self,
        stderr: str,
        project_root: Path,
    ) -> Optional[TestResult]:
        """Check stderr for compilation errors that prevented tests from running.

        When ts-jest or other transpilers fail, Jest exits with a non-zero code
        and no JSON report. This method detects those failures and returns a
        TestResult with the compilation error as an issue.

        Args:
            stderr: Standard error output from Jest.
            project_root: Project root directory.

        Returns:
            TestResult with compilation error issue, or None if no compilation error.
        """
        error_patterns = [
            "error TS",
            "SyntaxError",
            "Cannot find module",
            "Failed to parse the TypeScript config",
            "ts-node",
            "compilation failed",
            "Could not load",
        ]
        if not any(pattern in stderr for pattern in error_patterns):
            return None

        # Extract a concise error summary (first few meaningful lines)
        lines = stderr.strip().splitlines()
        summary_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("at "):
                summary_lines.append(stripped)
            if len(summary_lines) >= 5:
                break
        summary = "\n".join(summary_lines) if summary_lines else stderr[:500]

        issue = UnifiedIssue(
            id="jest-compilation-error",
            domain=ToolDomain.TESTING,
            source_tool=self.name,
            severity=Severity.HIGH,
            rule_id="compilation-error",
            title="Jest failed: TypeScript/JavaScript compilation error",
            description=summary,
            fixable=False,
        )

        result = TestResult(errors=1)
        result.issues.append(issue)
        LOGGER.warning(
            f"Jest compilation error detected: {summary_lines[0] if summary_lines else 'unknown'}"
        )
        return result

    def _parse_json_report(
        self,
        report_file: Path,
        project_root: Path,
    ) -> TestResult:
        """Parse Jest JSON report file.

        Delegates to base class _parse_json_report_file.
        """
        return self._parse_json_report_file(report_file, project_root)

    def _process_report(
        self,
        report,
        project_root,
    ) -> TestResult:
        """Process Jest JSON report (Jest-compatible format)."""
        return self._process_jest_report(report, project_root)
