"""Checkstyle linter plugin.

Checkstyle is a development tool to help programmers write Java code
that adheres to a coding standard.
https://checkstyle.org/
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Tuple

from lucidshark.core.logging import get_logger
from lucidshark.core.models import (
    ScanContext,
    Severity,
    ToolDomain,
    UnifiedIssue,
)
from lucidshark.core.subprocess_runner import run_with_streaming
from lucidshark.plugins.linters.base import LinterPlugin

LOGGER = get_logger(__name__)

# Checkstyle severity mapping
SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "ignore": Severity.INFO,
}


class CheckstyleLinter(LinterPlugin):
    """Checkstyle linter plugin for Java code analysis."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize CheckstyleLinter.

        Args:
            project_root: Optional project root for finding Checkstyle installation.
        """
        self._project_root = project_root

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "checkstyle"

    @property
    def languages(self) -> List[str]:
        """Supported languages."""
        return ["java"]

    @property
    def supports_fix(self) -> bool:
        """Checkstyle does not support auto-fix."""
        return False

    def get_version(self) -> str:
        """Get Checkstyle version."""
        try:
            binary, _ = self.ensure_binary()
            result = subprocess.run(
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Output: "Checkstyle version: X.Y.Z"
                return result.stdout.strip().split()[-1]
        except Exception:
            pass
        return "unknown"

    def _check_java_available(self) -> Optional[Path]:
        """Check if Java is available.

        Returns:
            Path to java binary or None if not found.
        """
        java_path = shutil.which("java")
        return Path(java_path) if java_path else None

    def ensure_binary(self) -> Tuple[Path, str]:
        """Ensure Checkstyle is available.

        Checks for:
        1. checkstyle command in PATH (standalone installation)

        Returns:
            Tuple of (path to checkstyle, mode: 'standalone' or 'jar').

        Raises:
            FileNotFoundError: If Checkstyle is not installed.
        """
        # Check for standalone checkstyle command
        checkstyle_path = shutil.which("checkstyle")
        if checkstyle_path:
            return Path(checkstyle_path), "standalone"

        raise FileNotFoundError(
            "Checkstyle is not installed. Install it with:\n"
            "  brew install checkstyle  (macOS)\n"
            "  apt install checkstyle   (Debian/Ubuntu)\n"
            "  OR use the Gradle/Maven Checkstyle plugin"
        )

    def lint(self, context: ScanContext) -> List[UnifiedIssue]:
        """Run Checkstyle linting.

        Args:
            context: Scan context with paths and configuration.

        Returns:
            List of linting issues.
        """
        try:
            binary, mode = self.ensure_binary()
        except FileNotFoundError as e:
            LOGGER.warning(str(e))
            return []

        # Determine config file
        config_file = self._find_config_file(context.project_root)

        # Build command for standalone checkstyle
        cmd = [
            str(binary),
            "-c", config_file,
            "-f", "xml",
        ]

        # Find Java source files
        java_files = self._find_java_files(context)
        if not java_files:
            LOGGER.info("No Java files found to check")
            return []

        cmd.extend(java_files)

        LOGGER.debug(f"Running: {' '.join(cmd[:10])}...")  # Truncate for readability

        try:
            result = run_with_streaming(
                cmd=cmd,
                cwd=context.project_root,
                tool_name="checkstyle",
                stream_handler=context.stream_handler,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            LOGGER.warning("Checkstyle timed out after 120 seconds")
            return []
        except Exception as e:
            LOGGER.error(f"Failed to run Checkstyle: {e}")
            return []

        # Parse XML output
        issues = self._parse_output(result.stdout, context.project_root)

        LOGGER.info(f"Checkstyle found {len(issues)} issues")
        return issues

    def _find_config_file(self, project_root: Path) -> str:
        """Find Checkstyle configuration file.

        Args:
            project_root: Project root directory.

        Returns:
            Path to config file or built-in config name.
        """
        # Check for custom config files
        custom_configs = [
            "checkstyle.xml",
            ".checkstyle.xml",
            "config/checkstyle/checkstyle.xml",
        ]

        for config in custom_configs:
            config_path = project_root / config
            if config_path.exists():
                return str(config_path)

        # Use built-in Google checks as default
        return "/google_checks.xml"

    def _find_java_files(self, context: ScanContext) -> List[str]:
        """Find Java source files to check.

        Args:
            context: Scan context.

        Returns:
            List of Java file paths.
        """
        java_files = []

        # Search in specified paths or common Java directories
        search_dirs = []
        if context.paths:
            search_dirs = list(context.paths)
        else:
            # Common Java source directories
            for src_dir in ["src", "src/main/java", "src/test/java"]:
                src_path = context.project_root / src_dir
                if src_path.exists():
                    search_dirs.append(src_path)

        if not search_dirs:
            search_dirs = [context.project_root]

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue

            for java_file in search_dir.rglob("*.java"):
                # Check if file should be excluded using proper gitignore matching
                if context.ignore_patterns is None or not context.ignore_patterns.matches(
                    java_file, context.project_root
                ):
                    java_files.append(str(java_file))

        return java_files

    def _parse_output(self, output: str, project_root: Path) -> List[UnifiedIssue]:
        """Parse Checkstyle XML output.

        Args:
            output: XML output from Checkstyle.
            project_root: Project root directory.

        Returns:
            List of UnifiedIssue objects.
        """
        if not output.strip():
            return []

        try:
            root = ET.fromstring(output)
        except ET.ParseError as e:
            LOGGER.warning(f"Failed to parse Checkstyle XML output: {e}")
            return []

        issues = []

        for file_elem in root.findall(".//file"):
            file_path = file_elem.get("name", "")

            for error_elem in file_elem.findall("error"):
                issue = self._error_to_issue(error_elem, file_path, project_root)
                if issue:
                    issues.append(issue)

        return issues

    def _error_to_issue(
        self,
        error_elem: ET.Element,
        file_path: str,
        project_root: Path,
    ) -> Optional[UnifiedIssue]:
        """Convert Checkstyle error element to UnifiedIssue.

        Args:
            error_elem: XML error element.
            file_path: File path from parent file element.
            project_root: Project root directory.

        Returns:
            UnifiedIssue or None.
        """
        try:
            line = error_elem.get("line")
            column = error_elem.get("column")
            severity_str = error_elem.get("severity", "error")
            message = error_elem.get("message", "")
            source = error_elem.get("source", "")

            # Extract rule name from source (e.g., "com.puppycrawl...WhitespaceAfterCheck")
            rule = source.split(".")[-1] if source else ""

            # Get severity
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            # Build file path
            path = Path(file_path)
            if not path.is_absolute():
                path = project_root / path

            # Parse line/column
            line_num = int(line) if line else None
            col_num = int(column) if column else None

            # Generate deterministic ID
            issue_id = self._generate_issue_id(
                rule, file_path, line_num, col_num, message
            )

            return UnifiedIssue(
                id=issue_id,
                domain=ToolDomain.LINTING,
                source_tool="checkstyle",
                severity=severity,
                rule_id=rule or "unknown",
                title=f"[{rule}] {message}" if rule else message,
                description=message,
                documentation_url=f"https://checkstyle.org/checks.html#{rule}" if rule else None,
                file_path=path,
                line_start=line_num,
                line_end=line_num,
                column_start=col_num,
                fixable=False,  # Checkstyle doesn't support auto-fix
                metadata={
                    "source": source,
                    "severity_raw": severity_str,
                },
            )
        except Exception as e:
            LOGGER.warning(f"Failed to parse Checkstyle error: {e}")
            return None

    def _generate_issue_id(
        self,
        rule: str,
        file: str,
        line: Optional[int],
        column: Optional[int],
        message: str,
    ) -> str:
        """Generate deterministic issue ID.

        Args:
            rule: Check/rule name.
            file: File path.
            line: Line number.
            column: Column number.
            message: Error message.

        Returns:
            Unique issue ID.
        """
        content = f"{rule}:{file}:{line or 0}:{column or 0}:{message}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"checkstyle-{rule}-{hash_val}" if rule else f"checkstyle-{hash_val}"
