"""Base class for formatter plugins.

All formatter plugins inherit from FormatterPlugin and implement the check() and fix() methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple, Union

from lucidshark.core.models import ScanContext, UnifiedIssue, ToolDomain
from lucidshark.plugins.linters.base import FixResult


class FormatterPlugin(ABC):
    """Abstract base class for formatter plugins.

    Formatter plugins provide code formatting checks for the quality pipeline.
    Each plugin wraps a specific formatting tool (ruff format, prettier, etc.).
    """

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        self._project_root = project_root

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin identifier (e.g., 'ruff_format', 'prettier')."""

    @property
    @abstractmethod
    def languages(self) -> List[str]:
        """Languages this formatter supports."""

    @property
    def domain(self) -> ToolDomain:
        """Tool domain (always FORMATTING for formatters)."""
        return ToolDomain.FORMATTING

    @property
    def supports_fix(self) -> bool:
        """Whether this formatter supports auto-fix mode. Formatters always support fix."""
        return True

    def get_version(self) -> str:
        """Get the version of the underlying formatting tool."""
        return "installed"

    @abstractmethod
    def ensure_binary(self) -> Union[Path, Tuple[Path, str]]:
        """Ensure the formatting tool is installed."""

    @abstractmethod
    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        """Check formatting without modifying files.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            List of UnifiedIssue objects for each formatting violation.
        """

    @abstractmethod
    def fix(self, context: ScanContext) -> FixResult:
        """Apply formatting fixes.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            FixResult with statistics about fixes applied.
        """

    def _resolve_paths(
        self,
        context: ScanContext,
        extensions: set[str],
        fallback_to_cwd: bool = False,
    ) -> List[str]:
        """Resolve and filter paths for formatting.

        Args:
            context: Scan context.
            extensions: File extensions this formatter handles (e.g., {".py"}).
            fallback_to_cwd: If True and no paths given, return ["."] (for tools
                that support directory recursion like ruff, prettier). If False
                and no paths given, discover files via rglob (for tools like
                rustfmt, google-java-format that need explicit file paths).

        Returns:
            List of path strings to pass to the formatter command.
        """
        if context.paths:
            paths_to_use = context.paths
            if context.ignore_patterns is not None:
                paths_to_use = [
                    p
                    for p in paths_to_use
                    if not context.ignore_patterns.matches(p, context.project_root)
                ]
            filtered: List[str] = []
            for path in paths_to_use:
                if path.is_dir():
                    if fallback_to_cwd:
                        filtered.append(str(path))
                    else:
                        # Tools that don't support dirs: find files within
                        for ext in extensions:
                            for f in path.rglob(f"*{ext}"):
                                if (
                                    context.ignore_patterns is None
                                    or not context.ignore_patterns.matches(
                                        f, context.project_root
                                    )
                                ):
                                    filtered.append(str(f))
                elif path.suffix.lower() in extensions:
                    filtered.append(str(path))
            return filtered

        if fallback_to_cwd:
            return ["."]

        # Discover files via rglob from project root
        found: List[str] = []
        for ext in extensions:
            for path in context.project_root.rglob(f"*{ext}"):
                if (
                    context.ignore_patterns is None
                    or not context.ignore_patterns.matches(path, context.project_root)
                ):
                    found.append(str(path))
        return found
