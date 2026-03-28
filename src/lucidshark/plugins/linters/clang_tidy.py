"""clang-tidy linter plugin.

clang-tidy is a clang-based C/C++ linter tool that provides diagnostics
and fixes for typical programming errors, style violations, and interface
misuse.
https://clang.llvm.org/extra/clang-tidy/
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    SkipReason,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.core.subprocess_runner import run_with_streaming
from lucidshark.plugins.c_utils import (
    C_EXTENSIONS,
    find_clang_tidy,
    generate_issue_id,
    get_clang_tidy_version,
)
from lucidshark.plugins.linters.base import FixResult, LinterPlugin

LOGGER = get_logger(__name__)

# Check category to severity mapping.
CHECK_SEVERITY = {
    # High severity - correctness & security
    "bugprone": Severity.HIGH,
    "cert": Severity.HIGH,
    "concurrency": Severity.HIGH,
    "clang-analyzer": Severity.HIGH,
    "security": Severity.HIGH,
    # Medium severity - potential bugs
    "misc": Severity.MEDIUM,
    "portability": Severity.MEDIUM,
    "performance": Severity.MEDIUM,
    # Low severity - style & modernization
    "readability": Severity.LOW,
    "modernize": Severity.LOW,
    "cppcoreguidelines": Severity.LOW,
    "hicpp": Severity.LOW,
    "llvm": Severity.LOW,
    "google": Severity.LOW,
}

# Diagnostic level to severity mapping.
LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
}

# Regex for parsing clang-tidy output:
#   file.c:42:5: warning: message [check-name]
_DIAG_RE = re.compile(
    r"^(.+):(\d+):(\d+):\s+(error|warning|note):\s+(.+?)(?:\s+\[([^\]]+)\])?$"
)


class ClangTidyLinter(LinterPlugin):
    """clang-tidy linter plugin for C code analysis."""

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        self._project_root = project_root

    @property
    def name(self) -> str:
        return "clang_tidy"

    @property
    def languages(self) -> List[str]:
        return ["c"]

    @property
    def supports_fix(self) -> bool:
        return True

    def get_version(self) -> str:
        return get_clang_tidy_version()

    def ensure_binary(self) -> Path:
        return find_clang_tidy()

    def lint(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        # Collect C source files to lint
        files = self._collect_c_files(context)
        if not files:
            LOGGER.debug("No C files to lint")
            return []

        cmd = [str(binary)] + files

        # Add compile_commands.json path if available
        from lucidshark.plugins.c_utils import has_build_dir

        build_dir = has_build_dir(context.project_root)
        if build_dir:
            cmd.insert(1, f"-p={build_dir}")

        LOGGER.debug(f"Running: {' '.join(cmd[:5])}... ({len(files)} files)")

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="clang-tidy",
                stream_handler=context.stream_handler,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("clang-tidy timed out after 300 seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.LINTING,
                reason=SkipReason.EXECUTION_FAILED,
                message="clang-tidy timed out after 300 seconds",
            )
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run clang-tidy: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.LINTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run clang-tidy: {e}",
            )
            return []

        # clang-tidy outputs diagnostics to stderr
        output = result.stderr or result.stdout or ""
        issues = self._parse_output(output, context.project_root)
        LOGGER.info(f"clang-tidy found {len(issues)} issues")
        return issues

    def fix(self, context: ScanContext) -> FixResult:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return FixResult()

        files = self._collect_c_files(context)
        if not files:
            return FixResult()

        pre_issues = self.lint(context)

        cmd = [str(binary), "--fix"] + files

        from lucidshark.plugins.c_utils import has_build_dir

        build_dir = has_build_dir(context.project_root)
        if build_dir:
            cmd.insert(1, f"-p={build_dir}")

        try:
            run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="clang-tidy-fix",
                stream_handler=context.stream_handler,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("clang-tidy fix timed out after 300 seconds")
            return FixResult()
        except Exception as e:
            LOGGER.debug(f"clang-tidy fix completed with: {e}")

        post_issues = self.lint(context)
        return self._calculate_fix_stats(pre_issues, post_issues)

    def _collect_c_files(self, context: ScanContext) -> List[str]:
        """Collect C source files from scan context."""
        if context.paths:
            files = []
            paths_to_use = context.paths
            if context.ignore_patterns is not None:
                paths_to_use = [
                    p
                    for p in paths_to_use
                    if not context.ignore_patterns.matches(p, context.project_root)
                ]
            for p in paths_to_use:
                if p.is_dir():
                    for ext in C_EXTENSIONS:
                        for f in p.rglob(f"*{ext}"):
                            if (
                                context.ignore_patterns is None
                                or not context.ignore_patterns.matches(
                                    f, context.project_root
                                )
                            ):
                                files.append(str(f))
                elif p.suffix.lower() in C_EXTENSIONS:
                    files.append(str(p))
            return files

        # Discover files from project root
        files = []
        for ext in C_EXTENSIONS:
            for f in context.project_root.rglob(f"*{ext}"):
                if (
                    context.ignore_patterns is None
                    or not context.ignore_patterns.matches(f, context.project_root)
                ):
                    files.append(str(f))
        return files

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse clang-tidy text output."""
        if not output.strip():
            return []

        issues: List[UnifiedIssue] = []
        seen_ids: set = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _DIAG_RE.match(line)
            if not match:
                continue

            file_str = match.group(1)
            line_num = int(match.group(2))
            col_num = int(match.group(3))
            level = match.group(4)
            message = match.group(5)
            check_name = match.group(6) or ""

            # Skip notes (supplementary info) - only report errors and warnings
            if level == "note":
                continue

            # Resolve file path
            file_path = Path(file_str)
            if not file_path.is_absolute():
                file_path = (project_root / file_path).resolve()
            else:
                file_path = file_path.resolve()

            severity = self._get_severity(check_name, level)
            title = f"[{check_name}] {message}" if check_name else message

            issue_id = generate_issue_id(
                "clang-tidy", check_name, str(file_path), line_num, col_num, message
            )

            if issue_id in seen_ids:
                continue
            seen_ids.add(issue_id)

            issues.append(
                UnifiedIssue(
                    id=issue_id,
                    domain=ToolDomain.LINTING,
                    source_tool="clang-tidy",
                    severity=severity,
                    rule_id=check_name or "unknown",
                    title=title,
                    description=message,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    column_start=col_num,
                    fixable=self.supports_fix,
                    metadata={
                        "check_name": check_name,
                        "level": level,
                    },
                )
            )

        return issues

    def _get_severity(self, check_name: str, level: str) -> Severity:
        """Get severity for a clang-tidy diagnostic."""
        # Check category-based severity first
        for category, severity in CHECK_SEVERITY.items():
            if check_name.startswith(category):
                return severity

        # Fall back to level-based severity
        return LEVEL_SEVERITY.get(level, Severity.MEDIUM)
