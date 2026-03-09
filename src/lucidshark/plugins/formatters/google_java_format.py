"""Google Java Format formatter plugin.

Wraps `google-java-format` for Java code formatting.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import List

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.core.subprocess_runner import run_with_streaming
from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.linters.base import FixResult
from lucidshark.plugins.utils import get_cli_version

LOGGER = get_logger(__name__)

JAVA_EXTENSIONS = {".java"}


class GoogleJavaFormatFormatter(FormatterPlugin):
    """Google Java Format plugin for Java code formatting."""

    @property
    def name(self) -> str:
        return "google_java_format"

    @property
    def languages(self) -> List[str]:
        return ["java"]

    def get_version(self) -> str:
        try:
            binary = self.ensure_binary()
            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        system_binary = shutil.which("google-java-format")
        if system_binary:
            return Path(system_binary)

        raise FileNotFoundError(
            "google-java-format is not installed. Install it from:\n"
            "  https://github.com/google/google-java-format/releases"
        )

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        paths = self._resolve_paths(context, JAVA_EXTENSIONS, fallback_to_cwd=False)
        if not paths:
            LOGGER.debug("No Java files to format-check")
            return []

        # google-java-format --dry-run outputs reformatted source code to stdout,
        # NOT file paths. We must check each file individually and use the exit code
        # from --set-exit-if-changed to determine which files need formatting.
        issues = []
        for file_path_str in paths:
            cmd = [str(binary), "--dry-run", "--set-exit-if-changed", file_path_str]

            try:
                result = run_with_streaming(
                    cmd=cmd,
                    cwd=context.project_root,
                    tool_name="google-java-format",
                    stream_handler=context.stream_handler,
                    timeout=120,
                )
            except subprocess.TimeoutExpired:
                LOGGER.warning(
                    f"google-java-format check timed out for {file_path_str}"
                )
                continue
            except Exception as e:
                LOGGER.error(
                    f"Failed to run google-java-format on {file_path_str}: {e}"
                )
                continue

            if result.returncode == 0:
                continue

            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                file_path = context.project_root / file_path

            content = f"google_java_format:{file_path_str}"
            hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]

            issues.append(
                UnifiedIssue(
                    id=f"google_java_format-format-{hash_val}",
                    domain=ToolDomain.FORMATTING,
                    source_tool="google_java_format",
                    severity=Severity.LOW,
                    rule_id="format",
                    title=f"File needs formatting: {file_path_str}",
                    description=f"File {file_path_str} does not match Google Java Format style.",
                    file_path=file_path,
                    fixable=True,
                    suggested_fix="Run google-java-format --replace to fix formatting.",
                )
            )

        LOGGER.info(f"google-java-format found {len(issues)} issues")
        return issues

    def fix(self, context: ScanContext) -> FixResult:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return FixResult()

        paths = self._resolve_paths(context, JAVA_EXTENSIONS, fallback_to_cwd=False)
        if not paths:
            return FixResult()

        cmd = [str(binary), "--replace"] + paths

        try:
            run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="google-java-format-fix",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except Exception as e:
            LOGGER.error(f"Failed to run google-java-format --replace: {e}")
            return FixResult()

        # Domain runner calls check() after fix to get remaining issues
        return FixResult(
            files_modified=len(paths),
            issues_fixed=0,
            issues_remaining=0,
        )
