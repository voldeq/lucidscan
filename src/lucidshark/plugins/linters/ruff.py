"""Ruff linter plugin.

Ruff is an extremely fast Python linter written in Rust.
https://github.com/astral-sh/ruff
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    SkipReason,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.plugins.linters.base import LinterPlugin, FixResult
from lucidshark.plugins.utils import ensure_python_binary, get_cli_version

LOGGER = get_logger(__name__)

# Python file extensions that Ruff supports
PYTHON_EXTENSIONS = {".py", ".pyi", ".pyw"}

# Ruff severity mapping
# Ruff outputs: E=error, W=warning, F=flake8, I=isort, etc.
# We map based on rule category
SEVERITY_MAP = {
    "E": Severity.MEDIUM,  # pycodestyle error
    "W": Severity.LOW,  # pycodestyle warning
    "F": Severity.MEDIUM,  # pyflakes
    "I": Severity.LOW,  # isort
    "N": Severity.LOW,  # pep8-naming
    "D": Severity.LOW,  # pydocstyle
    "UP": Severity.LOW,  # pyupgrade
    "YTT": Severity.MEDIUM,  # flake8-2020
    "ANN": Severity.LOW,  # flake8-annotations
    "ASYNC": Severity.MEDIUM,
    "S": Severity.HIGH,  # flake8-bandit (security)
    "BLE": Severity.MEDIUM,  # flake8-blind-except
    "FBT": Severity.LOW,  # flake8-boolean-trap
    "B": Severity.MEDIUM,  # flake8-bugbear
    "A": Severity.LOW,  # flake8-builtins
    "COM": Severity.LOW,  # flake8-commas
    "C4": Severity.LOW,  # flake8-comprehensions
    "DTZ": Severity.MEDIUM,  # flake8-datetimez
    "T10": Severity.HIGH,  # flake8-debugger
    "DJ": Severity.MEDIUM,  # flake8-django
    "EM": Severity.LOW,  # flake8-errmsg
    "EXE": Severity.LOW,  # flake8-executable
    "FA": Severity.LOW,  # flake8-future-annotations
    "ISC": Severity.LOW,  # flake8-implicit-str-concat
    "ICN": Severity.LOW,  # flake8-import-conventions
    "LOG": Severity.LOW,  # flake8-logging
    "G": Severity.LOW,  # flake8-logging-format
    "INP": Severity.LOW,  # flake8-no-pep420
    "PIE": Severity.LOW,  # flake8-pie
    "T20": Severity.LOW,  # flake8-print
    "PYI": Severity.LOW,  # flake8-pyi
    "PT": Severity.LOW,  # flake8-pytest-style
    "Q": Severity.LOW,  # flake8-quotes
    "RSE": Severity.LOW,  # flake8-raise
    "RET": Severity.LOW,  # flake8-return
    "SLF": Severity.MEDIUM,  # flake8-self
    "SLOT": Severity.LOW,  # flake8-slots
    "SIM": Severity.LOW,  # flake8-simplify
    "TID": Severity.LOW,  # flake8-tidy-imports
    "TCH": Severity.LOW,  # flake8-type-checking
    "INT": Severity.LOW,  # flake8-gettext
    "ARG": Severity.LOW,  # flake8-unused-arguments
    "PTH": Severity.LOW,  # flake8-use-pathlib
    "TD": Severity.INFO,  # flake8-todos
    "FIX": Severity.INFO,  # flake8-fixme
    "ERA": Severity.LOW,  # eradicate
    "PD": Severity.LOW,  # pandas-vet
    "PGH": Severity.LOW,  # pygrep-hooks
    "PL": Severity.MEDIUM,  # Pylint
    "TRY": Severity.LOW,  # tryceratops
    "FLY": Severity.LOW,  # flynt
    "NPY": Severity.MEDIUM,  # NumPy
    "PERF": Severity.LOW,  # Perflint
    "FURB": Severity.LOW,  # refurb
    "RUF": Severity.MEDIUM,  # Ruff-specific
}


class RuffLinter(LinterPlugin):
    """Ruff linter plugin for Python code analysis."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize RuffLinter.

        Args:
            project_root: Optional project root for finding Ruff installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "ruff"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["python"]

    @property
    def supports_fix(self) -> bool:
        """Ruff supports auto-fix."""
        return True

    def get_version(self) -> str:
        """Get Ruff version."""
        try:
            binary = self.ensure_binary()
            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        """Ensure Ruff binary is available.

        Checks for Ruff in project venv or system PATH.

        Returns:
            Path to Ruff binary.

        Raises:
            FileNotFoundError: If Ruff is not installed.
        """
        return ensure_python_binary(
            self._project_root,
            "ruff",
            "Ruff is not installed. Install it with:\n"
            "  pip install ruff\n"
            "  OR\n"
            "  uv add --dev ruff",
        )

    def _resolve_ruff_paths(self, context: ScanContext) -> Optional[List[str]]:
        """Resolve and filter paths for Ruff commands.

        Returns:
            List of path strings, or None if no applicable files.
        """
        if context.paths:
            paths_to_use = context.paths
            if context.ignore_patterns is not None:
                paths_to_use = [
                    p
                    for p in paths_to_use
                    if not context.ignore_patterns.matches(p, context.project_root)
                ]
            return self._filter_paths(paths_to_use, context.project_root) or None
        return ["."]

    def lint(self, context: ScanContext) -> List[UnifiedIssue]:
        """Run Ruff linting.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            List of linting issues.
        """
        binary = self._ensure_binary_safe()
        if binary is None:
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.LINTING,
                reason=SkipReason.TOOL_NOT_INSTALLED,
                message="Ruff is not installed",
                suggestion="pip install ruff",
            )
            return []

        cmd = [str(binary), "check", "--output-format", "json"]

        paths = self._resolve_ruff_paths(context)
        if not paths:
            LOGGER.debug("No Python files to lint")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.LINTING,
                reason=SkipReason.NO_APPLICABLE_FILES,
                message="No Python files to lint",
            )
            return []

        cmd.extend(paths)

        for pattern in self._get_ruff_exclude_patterns(context):
            cmd.extend(["--extend-exclude", pattern])

        LOGGER.debug(f"Running: {' '.join(cmd)}")

        stdout = self._run_linter_command(cmd, context, tool_label="ruff")
        if stdout is None:
            return []

        issues = self._parse_output(stdout, context.project_root)

        LOGGER.info(f"Ruff found {len(issues)} issues")
        return issues

    def fix(self, context: ScanContext) -> FixResult:
        """Apply Ruff auto-fixes.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            FixResult with statistics.
        """
        binary = self._ensure_binary_safe()
        if binary is None:
            return FixResult()

        pre_issues = self.lint(context)

        cmd = [str(binary), "check", "--fix", "--output-format", "json"]

        paths = self._resolve_ruff_paths(context)
        if not paths:
            LOGGER.debug("No Python files to fix")
            return FixResult()

        cmd.extend(paths)

        for pattern in self._get_ruff_exclude_patterns(context):
            cmd.extend(["--extend-exclude", pattern])

        LOGGER.debug(f"Running: {' '.join(cmd)}")

        stdout = self._run_linter_command(cmd, context, tool_label="ruff-fix")
        if stdout is None:
            return FixResult()

        post_issues = self._parse_output(stdout, context.project_root)
        return self._calculate_fix_stats(pre_issues, post_issues)

    @staticmethod
    def _simplify_exclude_pattern(pattern: str) -> str:
        """Simplify a gitignore-style glob into a form Ruff handles reliably.

        In gitignore semantics a bare name (e.g. ``.lucidshark``) matches that
        name at **any depth**, which is equivalent to ``**/.lucidshark/**``.
        Stripping the ``**/`` wrapper produces a simpler pattern that Ruff's
        globset can match reliably on every platform.

        Transformations applied (in order):
        - ``**/<name>/**`` → ``<name>``
        - ``**/<name>``    → ``<name>``
        - ``<path>/**``    → ``<path>``
        - everything else  → kept as-is, with backslashes normalised to ``/``
        """
        # Normalise separators first
        p = pattern.replace("\\", "/")

        # Strip leading **/ (matches any depth prefix)
        if p.startswith("**/"):
            p = p[3:]

        # Strip trailing /** (matches any depth suffix)
        if p.endswith("/**"):
            p = p[:-3]

        return p

    def _get_ruff_exclude_patterns(self, context: ScanContext) -> List[str]:
        """Get exclude patterns for Ruff, simplified for cross-platform reliability.

        Simplifies gitignore-style globs (e.g. ``**/.venv/**``) into bare
        directory names (e.g. ``.venv``) that Ruff's globset can match
        regardless of path separator conventions on the host OS.

        Args:
            context: Scan context with ignore patterns.

        Returns:
            List of patterns to pass to ``--extend-exclude``.
        """
        raw = context.get_exclude_patterns()
        seen: set[str] = set()
        result: list[str] = []
        for pattern in raw:
            simplified = self._simplify_exclude_pattern(pattern)
            if simplified and simplified not in seen:
                result.append(simplified)
                seen.add(simplified)
        return result

    def _filter_paths(
        self,
        paths: List[Path],
        project_root: Path,
    ) -> List[str]:
        """Filter paths to only include Python files.

        Directories are passed through as-is (Ruff will handle them).
        Files are filtered to only include supported extensions.

        Args:
            paths: List of paths to filter.
            project_root: Project root directory.

        Returns:
            List of filtered path strings.
        """
        filtered = []
        for path in paths:
            if path.is_dir():
                # Directories are passed through - Ruff will find Python files
                filtered.append(str(path))
            elif path.suffix.lower() in PYTHON_EXTENSIONS:
                # Only include files with Python extensions
                filtered.append(str(path))
            else:
                LOGGER.debug(f"Skipping non-Python file: {path}")
        return filtered

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse Ruff JSON output.

        Args:
            output: JSON output from Ruff.
            project_root: Project root directory.

        Returns:
            List of UnifiedIssue objects.
        """
        if not output.strip():
            return []

        try:
            violations = json.loads(output)
        except json.JSONDecodeError:
            LOGGER.warning("Failed to parse Ruff output as JSON")
            return []

        if not isinstance(violations, list):
            LOGGER.warning(f"Expected list from Ruff, got {type(violations).__name__}")
            return []

        issues = []
        for violation in violations:
            if not isinstance(violation, dict):
                LOGGER.warning(
                    f"Skipping non-dict violation: {type(violation).__name__}"
                )
                continue
            issue = self._violation_to_issue(violation, project_root)
            if issue:
                issues.append(issue)

        return issues

    def _violation_to_issue(
        self,
        violation: Dict[str, Any],
        project_root: Path,
    ) -> Optional[UnifiedIssue]:
        """Convert Ruff violation to UnifiedIssue.

        Args:
            violation: Ruff violation dict.
            project_root: Project root directory.

        Returns:
            UnifiedIssue or None.
        """
        try:
            code = violation.get("code", "")
            message = violation.get("message", "")
            filename = violation.get("filename", "")
            location = violation.get("location") or {}

            # Get severity based on rule category
            severity = self._get_severity(code)

            # Generate deterministic ID
            issue_id = self._generate_issue_id(code, filename, location, message)

            file_path = Path(filename)
            if not file_path.is_absolute():
                file_path = project_root / file_path

            # Extract code snippet if available
            code_snippet = None
            source_line = violation.get("source")
            if source_line:
                code_snippet = source_line

            # Extract fix information
            fix_info = violation.get("fix") or {}
            is_fixable = fix_info.get("applicability") == "safe" or bool(
                fix_info.get("edits")
            )
            fix_message = fix_info.get("message")

            return UnifiedIssue(
                id=issue_id,
                domain=ToolDomain.LINTING,
                source_tool="ruff",
                severity=severity,
                rule_id=code,
                title=f"{code}: {message}",
                description=message,
                documentation_url=violation.get("url"),
                file_path=file_path,
                line_start=location.get("row"),
                line_end=location.get("row"),
                column_start=location.get("column"),
                column_end=violation.get("end_location", {}).get("column"),
                code_snippet=code_snippet,
                fixable=is_fixable,
                suggested_fix=fix_message,
                recommendation=fix_message,
                metadata={
                    "noqa_row": violation.get("noqa_row"),
                },
            )
        except Exception as e:
            LOGGER.warning(f"Failed to parse violation: {e}")
            return None

    def _get_severity(self, code: str) -> Severity:
        """Get severity for a Ruff rule code.

        Args:
            code: Ruff rule code (e.g., 'E501', 'F401').

        Returns:
            Severity level.
        """
        # Extract category prefix (letters before numbers)
        prefix = ""
        for char in code:
            if char.isalpha():
                prefix += char
            else:
                break

        return SEVERITY_MAP.get(prefix, Severity.MEDIUM)

    def _generate_issue_id(
        self,
        code: str,
        filename: str,
        location: Dict[str, int],
        message: str,
    ) -> str:
        """Generate deterministic issue ID.

        Args:
            code: Rule code.
            filename: File path.
            location: Line/column info.
            message: Error message.

        Returns:
            Unique issue ID.
        """
        content = f"{code}:{filename}:{location.get('row', 0)}:{location.get('column', 0)}:{message}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"ruff-{code}-{hash_val}"
