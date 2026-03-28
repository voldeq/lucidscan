"""clang-format formatter plugin.

Wraps `clang-format` for C code formatting.
https://clang.llvm.org/docs/ClangFormat.html
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import List

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    SkipReason,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.core.subprocess_runner import run_with_streaming
from lucidshark.plugins.c_utils import C_EXTENSIONS, find_clang_format, get_clang_format_version
from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.linters.base import FixResult

LOGGER = get_logger(__name__)


class ClangFormatFormatter(FormatterPlugin):
    """clang-format formatter plugin for C code formatting."""

    @property
    def name(self) -> str:
        return "clang_format"

    @property
    def languages(self) -> List[str]:
        return ["c"]

    def get_version(self) -> str:
        return get_clang_format_version()

    def ensure_binary(self) -> Path:
        return find_clang_format()

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        paths = self._resolve_paths(context, C_EXTENSIONS, fallback_to_cwd=False)
        if not paths:
            LOGGER.debug("No C files to format-check")
            return []

        # clang-format --dry-run --Werror returns non-zero if formatting needed
        cmd = [str(binary), "--dry-run", "--Werror"] + paths

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="clang-format",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("clang-format check timed out after 120 seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.FORMATTING,
                reason=SkipReason.EXECUTION_FAILED,
                message="clang-format check timed out after 120 seconds",
            )
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run clang-format: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.FORMATTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run clang-format: {e}",
            )
            return []

        # clang-format --dry-run --Werror outputs warnings to stderr
        # for files that need reformatting
        stderr = result.stderr or ""
        if not stderr.strip() and result.returncode == 0:
            return []

        # Parse filenames from stderr warnings
        issues = []
        seen_files: set = set()
        for line in stderr.splitlines():
            line = line.strip()
            if not line:
                continue
            # Match lines like: path/file.c:10:5: warning: code should be clang-formatted
            # or simpler: just extract unique file paths from diagnostic lines
            for path_str in paths:
                if path_str in line and path_str not in seen_files:
                    seen_files.add(path_str)

                    file_path = Path(path_str)
                    if not file_path.is_absolute():
                        file_path = context.project_root / file_path

                    content = f"clang-format:{path_str}"
                    hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]

                    issues.append(
                        UnifiedIssue(
                            id=f"clang-format-{hash_val}",
                            domain=ToolDomain.FORMATTING,
                            source_tool="clang-format",
                            severity=Severity.LOW,
                            rule_id="format",
                            title=f"File needs formatting: {path_str}",
                            description=f"File {path_str} does not match clang-format style.",
                            file_path=file_path,
                            fixable=True,
                            suggested_fix="Run clang-format to fix formatting.",
                        )
                    )

        # If we got a non-zero exit but couldn't parse specific files,
        # create issues for all checked files
        if not issues and result.returncode != 0:
            for path_str in paths:
                file_path = Path(path_str)
                if not file_path.is_absolute():
                    file_path = context.project_root / file_path

                content = f"clang-format:{path_str}"
                hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]

                issues.append(
                    UnifiedIssue(
                        id=f"clang-format-{hash_val}",
                        domain=ToolDomain.FORMATTING,
                        source_tool="clang-format",
                        severity=Severity.LOW,
                        rule_id="format",
                        title=f"File needs formatting: {path_str}",
                        description=f"File {path_str} does not match clang-format style.",
                        file_path=file_path,
                        fixable=True,
                        suggested_fix="Run clang-format to fix formatting.",
                    )
                )

        LOGGER.info(f"clang-format found {len(issues)} issues")
        return issues

    def fix(self, context: ScanContext) -> FixResult:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return FixResult()

        paths = self._resolve_paths(context, C_EXTENSIONS, fallback_to_cwd=False)
        if not paths:
            return FixResult()

        cmd = [str(binary), "-i"] + paths

        try:
            run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="clang-format-fix",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except Exception as e:
            LOGGER.error(f"Failed to run clang-format: {e}")
            return FixResult()

        return FixResult(
            files_modified=len(paths),
            issues_fixed=0,
            issues_remaining=0,
        )
