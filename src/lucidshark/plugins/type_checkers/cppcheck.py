"""cppcheck type checker plugin.

cppcheck is a static analysis tool for C/C++ code that detects bugs,
undefined behaviour, and dangerous coding constructs that compilers
do not catch.
https://cppcheck.sourceforge.io/
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
    find_cppcheck,
    generate_issue_id,
    get_cppcheck_version,
)
from lucidshark.plugins.type_checkers.base import TypeCheckerPlugin

LOGGER = get_logger(__name__)

# cppcheck severity to LucidShark severity mapping.
CPPCHECK_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "style": Severity.LOW,
    "performance": Severity.MEDIUM,
    "portability": Severity.MEDIUM,
    "information": Severity.INFO,
}

# Template for parseable output: {file}:{line}:{column}: {severity}: {message} [{id}]
_TEMPLATE = "{file}:{line}:{column}: {severity}: {message} [{id}]"

# Regex matching the template output.
_DIAG_RE = re.compile(
    r"^(.+):(\d+):(\d+):\s+(error|warning|style|performance|portability|information):\s+(.+?)\s+\[([^\]]+)\]$"
)


class CppcheckChecker(TypeCheckerPlugin):
    """cppcheck plugin for C static analysis."""

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        self._project_root = project_root

    @property
    def name(self) -> str:
        return "cppcheck"

    @property
    def languages(self) -> List[str]:
        return ["c"]

    @property
    def supports_strict_mode(self) -> bool:
        return True

    def get_version(self) -> str:
        return get_cppcheck_version()

    def ensure_binary(self) -> Path:
        return find_cppcheck()

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        cmd = [
            str(binary),
            "--enable=all",
            "--language=c",
            f"--template={_TEMPLATE}",
            "--suppress=missingIncludeSystem",
            "--quiet",
        ]

        # Use strict mode (inconclusive checks) if configured
        if context.config and context.config.pipeline.type_checking:
            type_config = context.config.pipeline.type_checking
            for tool in type_config.tools:
                if tool.name == self.name and tool.strict:
                    cmd.append("--inconclusive")
                    break

        # Add paths to scan
        if context.paths:
            paths_to_use = context.paths
            if context.ignore_patterns is not None:
                paths_to_use = [
                    p
                    for p in paths_to_use
                    if not context.ignore_patterns.matches(p, context.project_root)
                ]
            for p in paths_to_use:
                cmd.append(str(p))
        else:
            cmd.append(str(context.project_root))

        LOGGER.debug(f"Running: {' '.join(cmd[:5])}...")

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="cppcheck",
                stream_handler=context.stream_handler,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("cppcheck timed out after 300 seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.TYPE_CHECKING,
                reason=SkipReason.EXECUTION_FAILED,
                message="cppcheck timed out after 300 seconds",
            )
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run cppcheck: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.TYPE_CHECKING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run cppcheck: {e}",
            )
            return []

        # cppcheck outputs diagnostics to stderr
        output = result.stderr or ""
        issues = self._parse_output(output, context.project_root)
        LOGGER.info(f"cppcheck found {len(issues)} issues")
        return issues

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse cppcheck template output."""
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
            cppcheck_severity = match.group(4)
            message = match.group(5)
            check_id = match.group(6)

            # Skip information-level messages
            if cppcheck_severity == "information":
                continue

            file_path = Path(file_str)
            if not file_path.is_absolute():
                file_path = (project_root / file_path).resolve()
            else:
                file_path = file_path.resolve()

            severity = CPPCHECK_SEVERITY.get(cppcheck_severity, Severity.MEDIUM)
            title = f"[{check_id}] {message}"

            issue_id = generate_issue_id(
                "cppcheck", check_id, str(file_path), line_num, col_num, message
            )

            if issue_id in seen_ids:
                continue
            seen_ids.add(issue_id)

            issues.append(
                UnifiedIssue(
                    id=issue_id,
                    domain=ToolDomain.TYPE_CHECKING,
                    source_tool="cppcheck",
                    severity=severity,
                    rule_id=check_id,
                    title=title,
                    description=message,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    column_start=col_num,
                    fixable=False,
                    metadata={
                        "cppcheck_severity": cppcheck_severity,
                        "check_id": check_id,
                    },
                )
            )

        return issues
