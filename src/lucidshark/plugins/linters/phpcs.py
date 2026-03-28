"""PHP_CodeSniffer (phpcs) linter plugin.

PHP_CodeSniffer tokenizes PHP files and detects violations of a defined set
of coding standards.
https://github.com/squizlabs/PHP_CodeSniffer
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import List, Optional

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.plugins.linters.base import FixResult, LinterPlugin

LOGGER = get_logger(__name__)

# phpcs severity mapping (phpcs uses type: ERROR or WARNING)
PHPCS_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
}

PHP_EXTENSIONS = {".php"}


def _find_phpcs(project_root: Optional[Path] = None) -> Path:
    """Find phpcs binary.

    Checks:
    1. Project vendor/bin/phpcs (Composer local install)
    2. System PATH

    Args:
        project_root: Optional project root.

    Returns:
        Path to phpcs binary.

    Raises:
        FileNotFoundError: If phpcs is not installed.
    """
    if project_root:
        vendor_bin = project_root / "vendor" / "bin" / "phpcs"
        if vendor_bin.exists():
            return vendor_bin

    system = shutil.which("phpcs")
    if system:
        return Path(system)

    raise FileNotFoundError(
        "PHP_CodeSniffer is not installed. "
        "Install via: composer require --dev squizlabs/php_codesniffer"
    )


def _find_phpcbf(project_root: Optional[Path] = None) -> Optional[Path]:
    """Find phpcbf binary (auto-fixer companion to phpcs).

    Args:
        project_root: Optional project root.

    Returns:
        Path to phpcbf binary, or None.
    """
    if project_root:
        vendor_bin = project_root / "vendor" / "bin" / "phpcbf"
        if vendor_bin.exists():
            return vendor_bin

    system = shutil.which("phpcbf")
    if system:
        return Path(system)

    return None


class PhpcsLinter(LinterPlugin):
    """PHP_CodeSniffer linter plugin for PHP code analysis."""

    def __init__(self, project_root: Optional[Path] = None, **kwargs) -> None:
        self._project_root = project_root

    @property
    def name(self) -> str:
        return "phpcs"

    @property
    def languages(self) -> List[str]:
        return ["php"]

    @property
    def supports_fix(self) -> bool:
        return True

    def get_version(self) -> str:
        try:
            binary = self.ensure_binary()
            from lucidshark.plugins.utils import get_cli_version

            return get_cli_version(binary)
        except FileNotFoundError:
            return "unknown"

    def ensure_binary(self) -> Path:
        return _find_phpcs(self._project_root)

    def lint(self, context: ScanContext) -> List[UnifiedIssue]:
        try:
            binary = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        paths = self._resolve_paths(context)
        if not paths:
            LOGGER.debug("No PHP files to lint")
            return []

        cmd = [
            str(binary),
            "--report=json",
            "--no-colors",
        ] + paths

        stdout = self._run_linter_command(cmd, context, tool_label="phpcs", timeout=300)
        if stdout is None:
            return []

        issues = self._parse_output(stdout, context.project_root)
        LOGGER.info(f"phpcs found {len(issues)} issues")
        return issues

    def fix(self, context: ScanContext) -> FixResult:
        phpcbf = _find_phpcbf(self._project_root)
        if not phpcbf:
            LOGGER.warning("phpcbf not found, cannot auto-fix")
            return FixResult()

        paths = self._resolve_paths(context)
        if not paths:
            return FixResult()

        pre_issues = self.lint(context)

        cmd = [str(phpcbf)] + paths

        self._run_linter_command(cmd, context, tool_label="phpcbf", timeout=300)

        post_issues = self.lint(context)
        return self._calculate_fix_stats(pre_issues, post_issues)

    def _resolve_paths(self, context: ScanContext) -> List[str]:
        """Resolve PHP file paths from context."""
        if context.paths:
            filtered = []
            for path in context.paths:
                if path.is_dir():
                    filtered.append(str(path))
                elif path.suffix.lower() in PHP_EXTENSIONS:
                    filtered.append(str(path))
            return filtered

        # Default to project root
        return ["."]

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse phpcs JSON output.

        phpcs --report=json produces:
        {
          "totals": {"errors": N, "warnings": N, ...},
          "files": {
            "/path/to/file.php": {
              "messages": [
                {"message": "...", "source": "rule.id", "severity": 5,
                 "fixable": true, "type": "ERROR", "line": 10, "column": 5}
              ]
            }
          }
        }
        """
        if not output.strip():
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            LOGGER.warning("Failed to parse phpcs JSON output")
            return []

        files = data.get("files", {})
        issues = []
        seen_ids = set()

        for file_path_str, file_data in files.items():
            messages = file_data.get("messages", [])
            for msg in messages:
                issue = self._message_to_issue(msg, file_path_str, project_root)
                if issue and issue.id not in seen_ids:
                    issues.append(issue)
                    seen_ids.add(issue.id)

        return issues

    def _message_to_issue(
        self, msg: dict, file_path_str: str, project_root: Path
    ) -> Optional[UnifiedIssue]:
        try:
            message_text = msg.get("message", "")
            source = msg.get("source", "")
            msg_type = msg.get("type", "ERROR")
            line = msg.get("line")
            column = msg.get("column")
            fixable = msg.get("fixable", False)

            severity = PHPCS_SEVERITY_MAP.get(msg_type, Severity.MEDIUM)

            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                file_path = project_root / file_path

            title = f"[{source}] {message_text}" if source else message_text

            issue_id = self._generate_issue_id(
                source, file_path_str, line, column, message_text
            )

            return UnifiedIssue(
                id=issue_id,
                domain=ToolDomain.LINTING,
                source_tool="phpcs",
                severity=severity,
                rule_id=source or "phpcs",
                title=title,
                description=message_text,
                file_path=file_path,
                line_start=line,
                line_end=line,
                column_start=column,
                fixable=fixable,
                metadata={
                    "type": msg_type,
                    "source": source,
                },
            )
        except Exception as e:
            LOGGER.warning(f"Failed to parse phpcs message: {e}")
            return None

    def _generate_issue_id(
        self,
        rule_id: str,
        file_path: str,
        line: Optional[int],
        column: Optional[int],
        message: str,
    ) -> str:
        content = f"phpcs:{rule_id}:{file_path}:{line}:{column}:{message}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        prefix = f"phpcs-{rule_id}-" if rule_id else "phpcs-"
        return f"{prefix}{hash_val}"
