"""Mocha test runner plugin.

Mocha is a feature-rich JavaScript test framework running on Node.js,
making asynchronous testing simple and fun.
https://mochajs.org/
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

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

# Mocha config file names in order of preference
MOCHA_CONFIG_FILES = [
    ".mocharc.yml",
    ".mocharc.yaml",
    ".mocharc.json",
    ".mocharc.js",
    ".mocharc.cjs",
    ".mocharc.mjs",
]


class MochaRunner(TestRunnerPlugin):
    """Mocha test runner plugin for JavaScript/TypeScript test execution.

    Mocha uses a different JSON output format than Jest/Vitest. The ``--reporter json``
    flag produces output with ``stats``, ``tests``, ``passes``, ``failures``, and
    ``pending`` top-level keys.

    Coverage is handled externally via NYC (Istanbul CLI) rather than a built-in flag.
    When NYC is available, the runner wraps the mocha command with ``nyc`` to produce
    coverage data automatically.
    """

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize MochaRunner.

        Args:
            project_root: Optional project root for finding Mocha installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "mocha"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["javascript", "typescript"]

    def ensure_binary(self) -> Path:
        """Ensure Mocha is available."""
        return ensure_node_binary(
            self._project_root,
            "mocha",
            "Mocha is not installed. Install it with:\n"
            "  npm install mocha --save-dev\n"
            "  OR\n"
            "  npm install -g mocha",
        )

    def _find_nyc_binary(self) -> Optional[Path]:
        """Find NYC (Istanbul CLI) binary for coverage instrumentation.

        Returns:
            Path to nyc binary, or None if not installed.
        """
        try:
            return ensure_node_binary(
                self._project_root,
                "nyc",
                "",  # No install instructions — NYC is optional
            )
        except FileNotFoundError:
            return None

    def _find_mocha_config(self, project_root: Path) -> Optional[Path]:
        """Find Mocha configuration file.

        Args:
            project_root: Project root directory.

        Returns:
            Path to mocha config or None.
        """
        for config_name in MOCHA_CONFIG_FILES:
            config_path = project_root / config_name
            if config_path.exists():
                return config_path
        return None

    def run_tests(self, context: ScanContext) -> TestResult:
        """Run Mocha on the specified paths.

        If NYC is available, wraps the command with ``nyc`` to produce coverage
        data automatically.

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

        cmd: List[str] = []

        # Wrap with NYC for coverage if available
        nyc_binary = self._find_nyc_binary()
        if nyc_binary:
            cmd.extend(
                [
                    str(nyc_binary),
                    "--reporter=json",
                    "--reporter=text",
                    "--",
                ]
            )
            LOGGER.debug("NYC found, wrapping mocha with coverage instrumentation")

        cmd.extend(
            [
                str(binary),
                "--reporter",
                "json",
                "--exit",  # Force Mocha to exit after tests complete
            ]
        )

        if context.paths:
            paths = [str(p) for p in context.paths]
            cmd.extend(paths)

        LOGGER.debug(f"Running: {' '.join(cmd)}")

        result = self._run_test_subprocess(cmd, context)
        if result is None:
            return TestResult()

        # After NYC-wrapped run, generate coverage-summary.json for Istanbul plugin
        if nyc_binary:
            nyc_output_dir = context.project_root / ".nyc_output"
            if nyc_output_dir.exists():
                try:
                    subprocess.run(
                        [
                            str(nyc_binary),
                            "report",
                            "--reporter=json-summary",
                            f"--report-dir={context.project_root / 'coverage'}",
                        ],
                        cwd=str(context.project_root),
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    LOGGER.debug("Generated NYC coverage-summary.json")
                except Exception as e:
                    LOGGER.warning(f"Failed to generate NYC coverage summary: {e}")

        # Mocha outputs JSON to stdout when using --reporter json
        return self._parse_mocha_output(
            result.stdout, result.stderr, context.project_root
        )

    def _parse_mocha_output(
        self,
        stdout: str,
        stderr: str,
        project_root: Path,
    ) -> TestResult:
        """Parse Mocha JSON reporter output from stdout.

        Mocha's JSON reporter outputs to stdout with structure::

            {
                "stats": { "suites", "tests", "passes", "pending",
                           "failures", "start", "end", "duration" },
                "tests": [...],
                "pending": [...],
                "failures": [...],
                "passes": [...]
            }

        When NYC wraps mocha, it may prepend coverage output to stdout.
        We extract the JSON portion from the output.

        Args:
            stdout: Standard output from Mocha.
            stderr: Standard error from Mocha.
            project_root: Project root directory.

        Returns:
            TestResult with parsed data.
        """
        if not stdout.strip():
            return TestResult()

        json_str = self._extract_json(stdout)
        if not json_str:
            LOGGER.warning("Could not extract JSON from Mocha output")
            return TestResult()

        try:
            report = json.loads(json_str)
        except json.JSONDecodeError as e:
            LOGGER.warning(f"Failed to parse Mocha JSON output: {e}")
            return TestResult()

        return self._process_mocha_report(report, project_root)

    def _extract_json(self, output: str) -> Optional[str]:
        """Extract JSON object from output that may contain non-JSON prefix/suffix.

        When NYC wraps mocha, coverage text may appear before or after the JSON.
        This method finds the outermost ``{...}`` block.

        Args:
            output: Raw stdout output.

        Returns:
            JSON string or None.
        """
        # Try parsing the full output first
        stripped = output.strip()
        if stripped.startswith("{"):
            try:
                json.loads(stripped)
                return stripped
            except json.JSONDecodeError:
                pass

        # Find the first '{' and try to extract from there
        start = output.find("{")
        if start == -1:
            return None

        # Walk backwards from end to find matching closing brace
        end = output.rfind("}")
        if end == -1 or end <= start:
            return None

        candidate = output[start : end + 1]
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            return None

    def _process_mocha_report(
        self,
        report: Dict[str, Any],
        project_root: Path,
    ) -> TestResult:
        """Process Mocha JSON reporter output.

        Args:
            report: Parsed JSON report from Mocha.
            project_root: Project root directory.

        Returns:
            TestResult with processed data.
        """
        stats = report.get("stats", {})
        num_passed = stats.get("passes", 0)
        num_failed = stats.get("failures", 0)
        num_pending = stats.get("pending", 0)
        duration_ms = stats.get("duration", 0)

        result = TestResult(
            passed=num_passed,
            failed=num_failed,
            skipped=num_pending,
            errors=0,
            duration_ms=duration_ms,
        )

        # Convert failures to issues
        failures = report.get("failures", [])
        for failure in failures:
            issue = self._failure_to_issue(failure, project_root)
            if issue:
                result.issues.append(issue)

        LOGGER.info(
            f"Mocha: {result.passed} passed, {result.failed} failed, "
            f"{result.skipped} skipped"
        )
        return result

    def _failure_to_issue(
        self,
        failure: Dict[str, Any],
        project_root: Path,
    ) -> Optional[UnifiedIssue]:
        """Convert a Mocha test failure to a UnifiedIssue.

        Mocha failure object structure::

            {
                "title": "test name",
                "fullTitle": "Suite Name test name",
                "duration": 5,
                "err": {
                    "message": "expected 1 to equal 2",
                    "stack": "AssertionError: expected 1 to equal 2\\n    at Context.<anonymous> (test/app.test.js:10:20)"
                }
            }

        Args:
            failure: Mocha failure object.
            project_root: Project root directory.

        Returns:
            UnifiedIssue or None.
        """
        try:
            full_title = failure.get("fullTitle", "")
            title = failure.get("title", "")
            err = failure.get("err", {})
            message = err.get("message", "Test failed")
            stack = err.get("stack", "")

            # Extract file path and line from stack trace
            file_path, line_number = self._extract_location(stack, project_root)

            # Generate deterministic ID
            assertion_text = self._extract_assertion(message)
            issue_id = self._generate_issue_id(full_title, assertion_text)

            display_title = (
                f"{full_title}: {assertion_text}"
                if assertion_text
                else f"{full_title} failed"
            )

            return UnifiedIssue(
                id=issue_id,
                domain=ToolDomain.TESTING,
                source_tool=self.name,
                severity=Severity.HIGH,
                rule_id="failed",
                title=display_title,
                description=message,
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                fixable=False,
                metadata={
                    "full_title": full_title,
                    "title": title,
                    "error_message": message,
                    "stack": stack,
                    "assertion": assertion_text,
                },
            )
        except Exception as e:
            LOGGER.warning(f"Failed to parse Mocha test failure: {e}")
            return None

    def _extract_location(
        self,
        stack: str,
        project_root: Path,
    ) -> tuple[Optional[Path], Optional[int]]:
        """Extract file path and line number from a Mocha stack trace.

        Matches patterns like:
        - ``at Context.<anonymous> (test/app.test.js:10:20)``
        - ``at test/app.test.ts:10:20``

        Args:
            stack: Stack trace string.
            project_root: Project root directory.

        Returns:
            Tuple of (file_path, line_number) or (None, None).
        """
        if not stack:
            return None, None

        # Patterns for extracting location from stack traces
        patterns = [
            # Parenthesized: at Context.<anonymous> (path:line:col)
            r"\(([^)]+\.(?:spec|test)\.(?:js|ts|mjs|cjs|mts|cts|jsx|tsx)):(\d+):\d+\)",
            r"\(([^)]+\.(?:js|ts|mjs|cjs|mts|cts|jsx|tsx)):(\d+):\d+\)",
            # Non-parenthesized: at path:line:col
            r"at\s+([^\s]+\.(?:spec|test)\.(?:js|ts|mjs|cjs|mts|cts|jsx|tsx)):(\d+):\d+",
            r"at\s+([^\s]+\.(?:js|ts|mjs|cjs|mts|cts|jsx|tsx)):(\d+):\d+",
        ]

        for pattern in patterns:
            match = re.search(pattern, stack)
            if match:
                file_str = match.group(1)
                line_num = int(match.group(2))
                file_path = Path(file_str)
                if not file_path.is_absolute():
                    file_path = project_root / file_path
                return file_path, line_num

        return None, None

    def _extract_assertion(self, message: str) -> str:
        """Extract a concise assertion summary from a Mocha failure message.

        Args:
            message: Error message from Mocha.

        Returns:
            Extracted assertion or truncated message.
        """
        if not message:
            return ""

        lines = message.strip().split("\n")

        # Look for common assertion patterns
        for line in lines:
            line = line.strip()
            # Chai expect: expected X to equal Y
            if line.startswith("expected "):
                return line[:100]
            # assert: AssertionError
            if "AssertionError" in line or "AssertionError" in line:
                return line[:100]
            # expect(X).to.equal(Y) style
            if line.startswith("expect("):
                return line[:100]
            # Expected: / Received: pattern
            if line.startswith("Expected:"):
                idx = lines.index(line) if line in lines else -1
                if idx >= 0 and idx + 1 < len(lines):
                    received = lines[idx + 1].strip()
                    return f"{line} {received}"[:100]
                return line[:100]

        # Fallback: return first meaningful line
        for line in lines:
            line = line.strip()
            if line and not line.startswith("at ") and len(line) > 5:
                return line[:100]

        return message[:100]

    # _generate_issue_id inherited from TestRunnerPlugin base class
