"""Base class for linter plugins.

All linter plugins inherit from LinterPlugin and implement the lint() method.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Union

from lucidshark.core.logging import get_logger
from lucidshark.core.models import ScanContext, SkipReason, UnifiedIssue, ToolDomain
from lucidshark.core.subprocess_runner import run_with_streaming

LOGGER = get_logger(__name__)


@dataclass
class FixResult:
    """Result of applying automatic fixes."""

    files_modified: int = 0
    issues_fixed: int = 0
    issues_remaining: int = 0
    details: List[str] = None  # type: ignore

    def __post_init__(self):
        if self.details is None:
            self.details = []


class LinterPlugin(ABC):
    """Abstract base class for linter plugins.

    Linter plugins provide code linting functionality for the quality pipeline.
    Each plugin wraps a specific linting tool (Ruff, ESLint, etc.).
    """

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        """Initialize the linter plugin.

        Args:
            project_root: Optional project root for tool installation.
            **kwargs: Additional arguments for subclasses.
        """
        self._project_root = project_root

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin identifier (e.g., 'ruff', 'eslint').

        Returns:
            Plugin name string.
        """

    @property
    @abstractmethod
    def languages(self) -> List[str]:
        """Languages this linter supports.

        Returns:
            List of language names (e.g., ['python'], ['javascript', 'typescript']).
        """

    @property
    def domain(self) -> ToolDomain:
        """Tool domain (always LINTING for linters).

        Returns:
            ToolDomain.LINTING
        """
        return ToolDomain.LINTING

    @property
    def supports_fix(self) -> bool:
        """Whether this linter supports auto-fix mode.

        Returns:
            True if the linter can automatically fix issues.
        """
        return False

    def get_version(self) -> str:
        """Get the version of the underlying linting tool.

        Returns:
            Version string. Default returns "installed" since version
            management is handled by package managers.
        """
        return "installed"

    @abstractmethod
    def ensure_binary(self) -> Union[Path, Tuple[Path, str]]:
        """Ensure the linting tool is installed.

        Downloads or installs the tool if not present.

        Returns:
            Path to the tool binary, or tuple of (path, mode) for tools
            that need additional context (e.g., checkstyle standalone vs jar).
        """

    @abstractmethod
    def lint(self, context: ScanContext) -> List[UnifiedIssue]:
        """Run linting on the specified paths.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            List of UnifiedIssue objects for each linting violation.
        """

    def _ensure_binary_safe(self) -> Optional[Path]:
        """Ensure binary is available, returning None instead of raising.

        Returns:
            Path to binary, or None if not found.
        """
        try:
            result = self.ensure_binary()
            # ensure_binary may return a tuple (path, mode)
            if isinstance(result, tuple):
                return result[0]
            return result
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return None

    def _run_linter_command(
        self,
        cmd: List[str],
        context: ScanContext,
        tool_label: Optional[str] = None,
        timeout: int = 120,
    ) -> Optional[str]:
        """Run a linter command with standard timeout and error handling.

        Args:
            cmd: Command to execute.
            context: Scan context for recording skips.
            tool_label: Tool name for logging (defaults to self.name).
            timeout: Timeout in seconds (default 120).

        Returns:
            stdout on success, or None on timeout/error.
        """
        label = tool_label or self.name
        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name=label,
                stream_handler=context.stream_handler,
                timeout=timeout,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            LOGGER.warning(f"{label} timed out after {timeout} seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.LINTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"{label} timed out after {timeout} seconds",
            )
            return None
        except Exception as e:
            LOGGER.error(f"Failed to run {label}: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.LINTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run {label}: {e}",
            )
            return None

    @staticmethod
    def _calculate_fix_stats(
        pre_issues: List[UnifiedIssue],
        post_issues: List[UnifiedIssue],
    ) -> FixResult:
        """Calculate fix statistics from pre/post issue comparison.

        Args:
            pre_issues: Issues before fix.
            post_issues: Issues after fix.

        Returns:
            FixResult with computed statistics.
        """
        files_modified = len(
            set(
                str(issue.file_path) for issue in pre_issues if issue not in post_issues
            )
        )
        return FixResult(
            files_modified=files_modified,
            issues_fixed=len(pre_issues) - len(post_issues),
            issues_remaining=len(post_issues),
        )

    def fix(self, context: ScanContext) -> FixResult:
        """Apply automatic fixes for linting issues.

        Override this method if the linter supports auto-fix.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            FixResult with statistics about fixes applied.

        Raises:
            NotImplementedError: If the linter doesn't support auto-fix.
        """
        raise NotImplementedError(f"{self.name} does not support auto-fix")
