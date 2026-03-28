"""PHP-CS-Fixer formatter plugin.

PHP Coding Standards Fixer fixes code to follow standards.
https://cs.symfony.com/
"""

from __future__ import annotations

import hashlib
import json
import shutil
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
from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.linters.base import FixResult

LOGGER = get_logger(__name__)

PHP_EXTENSIONS = {".php"}


def _find_php_cs_fixer(project_root: Optional[Path] = None) -> Path:
    """Find php-cs-fixer binary.

    Checks:
    1. Project vendor/bin/php-cs-fixer (Composer local install)
    2. System PATH

    Args:
        project_root: Optional project root.

    Returns:
        Path to php-cs-fixer binary.

    Raises:
        FileNotFoundError: If php-cs-fixer is not installed.
    """
    if project_root:
        vendor_bin = project_root / "vendor" / "bin" / "php-cs-fixer"
        if vendor_bin.exists():
            return vendor_bin

    system = shutil.which("php-cs-fixer")
    if system:
        return Path(system)

    raise FileNotFoundError(
        "PHP-CS-Fixer is not installed. "
        "Install via: composer require --dev friendsofphp/php-cs-fixer"
    )


class PhpCsFixerFormatter(FormatterPlugin):
    """PHP-CS-Fixer formatter plugin for PHP code formatting."""

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        self._project_root = project_root

    @property
    def name(self) -> str:
        return "php_cs_fixer"

    @property
    def languages(self) -> List[str]:
        return ["php"]

    def get_version(self) -> str:
        try:
            binary = self.ensure_binary()
            from lucidshark.plugins.utils import get_cli_version

            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        return _find_php_cs_fixer(self._project_root)

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        paths = self._resolve_paths(context, PHP_EXTENSIONS, fallback_to_cwd=True)
        if not paths:
            LOGGER.debug("No PHP files to format-check")
            return []

        # php-cs-fixer fix --dry-run --diff --format=json reports files that need fixing
        cmd = [
            str(binary),
            "fix",
            "--dry-run",
            "--format=json",
            "--no-interaction",
        ] + paths

        LOGGER.debug(f"Running: {' '.join(cmd)}")

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="php-cs-fixer",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("php-cs-fixer check timed out after 120 seconds")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.FORMATTING,
                reason=SkipReason.EXECUTION_FAILED,
                message="php-cs-fixer check timed out after 120 seconds",
            )
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run php-cs-fixer: {e}")
            context.record_skip(
                tool_name=self.name,
                domain=ToolDomain.FORMATTING,
                reason=SkipReason.EXECUTION_FAILED,
                message=f"Failed to run php-cs-fixer: {e}",
            )
            return []

        return self._parse_output(result.stdout, context.project_root)

    def fix(self, context: ScanContext) -> FixResult:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return FixResult()

        paths = self._resolve_paths(context, PHP_EXTENSIONS, fallback_to_cwd=True)
        if not paths:
            return FixResult()

        cmd = [
            str(binary),
            "fix",
            "--format=json",
            "--no-interaction",
        ] + paths

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="php-cs-fixer-fix",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except Exception as e:
            LOGGER.error(f"Failed to run php-cs-fixer fix: {e}")
            return FixResult()

        # Parse output to determine how many files were fixed
        files_modified = 0
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                files_data = data.get("files", [])
                files_modified = len(files_data)
            except json.JSONDecodeError:
                pass

        return FixResult(
            files_modified=files_modified,
            issues_fixed=files_modified,
            issues_remaining=0,
        )

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse php-cs-fixer JSON output.

        php-cs-fixer --format=json produces:
        {
          "files": [
            {"name": "src/Foo.php", "appliedFixers": ["braces", "line_ending"]}
          ]
        }
        """
        if not output or not output.strip():
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            LOGGER.warning("Failed to parse php-cs-fixer JSON output")
            return []

        files_data = data.get("files", [])
        issues = []

        for file_data in files_data:
            file_name = file_data.get("name", "")
            applied_fixers = file_data.get("appliedFixers", [])

            if not file_name:
                continue

            file_path = Path(file_name)
            if not file_path.is_absolute():
                file_path = project_root / file_path

            fixers_str = ", ".join(applied_fixers) if applied_fixers else "formatting"

            content = f"php-cs-fixer:{file_name}:{fixers_str}"
            hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]

            issues.append(
                UnifiedIssue(
                    id=f"php-cs-fixer-{hash_val}",
                    domain=ToolDomain.FORMATTING,
                    source_tool="php_cs_fixer",
                    severity=Severity.LOW,
                    rule_id="format",
                    title=f"File needs formatting: {file_name}",
                    description=(
                        f"File {file_name} does not match PHP-CS-Fixer style. "
                        f"Rules: {fixers_str}"
                    ),
                    file_path=file_path,
                    fixable=True,
                    suggested_fix="Run php-cs-fixer fix to format.",
                    metadata={
                        "applied_fixers": applied_fixers,
                    },
                )
            )

        LOGGER.info(f"php-cs-fixer found {len(issues)} formatting issues")
        return issues
