"""Doctor command implementation.

Self-diagnosis tool to check LucidShark setup and environment health.
"""

from __future__ import annotations

import sys
import subprocess
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from lucidshark.config.models import LucidSharkConfig

from lucidshark.bootstrap.paths import get_lucidshark_home, LucidsharkPaths
from lucidshark.bootstrap.platform import get_platform_info
from lucidshark.bootstrap.validation import validate_binary, ToolStatus
from lucidshark.cli.commands import Command
from lucidshark.cli.exit_codes import EXIT_SUCCESS, EXIT_ISSUES_FOUND
from lucidshark.config.loader import find_project_config
from lucidshark.config.validation import validate_config_file
from lucidshark.plugins.scanners import discover_scanner_plugins


class CheckResult:
    """Result of a single health check."""

    def __init__(self, name: str, passed: bool, message: str, hint: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
        self.hint = hint

    @property
    def status_icon(self) -> str:
        """Return status icon for display."""
        return "[OK]" if self.passed else "[!!]"


class DoctorCommand(Command):
    """Self-diagnosis tool to check LucidShark setup."""

    def __init__(self, version: str):
        """Initialize DoctorCommand.

        Args:
            version: Current lucidshark version string.
        """
        self._version = version

    @property
    def name(self) -> str:
        """Command identifier."""
        return "doctor"

    def execute(self, args: Namespace, config: "LucidSharkConfig | None" = None) -> int:
        """Execute the doctor command.

        Runs health checks and displays results.

        Args:
            args: Parsed command-line arguments.
            config: Optional LucidShark configuration.

        Returns:
            Exit code (0 if all checks pass, 1 if any fail).
        """
        print(f"lucidshark doctor v{self._version}\n")

        results: List[CheckResult] = []
        project_root = Path.cwd()

        # Run all checks
        results.extend(self._check_configuration(project_root))
        results.extend(self._check_tools(project_root))
        results.extend(self._check_environment())
        results.extend(self._check_integrations())

        # Print results by category
        self._print_results(results)

        # Summary
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)

        print(f"\nSummary: {passed} passed, {failed} issues")

        if failed > 0:
            print("\nRun suggested commands to fix issues.")
            return EXIT_ISSUES_FOUND

        return EXIT_SUCCESS

    def _check_configuration(self, project_root: Path) -> List[CheckResult]:
        """Check configuration file status.

        Args:
            project_root: Project root directory.

        Returns:
            List of check results.
        """
        results: List[CheckResult] = []

        # Check if config file exists
        config_path = find_project_config(project_root)

        if config_path is None:
            results.append(CheckResult(
                "config_file",
                False,
                "No lucidshark.yml found",
                "Run 'lucidshark autoconfigure' to generate configuration",
            ))
            return results

        results.append(CheckResult(
            "config_file",
            True,
            f"Found {config_path.name}",
        ))

        # Validate config
        is_valid, issues = validate_config_file(config_path)
        errors = [i for i in issues if i.severity.value == "error"]
        warnings = [i for i in issues if i.severity.value == "warning"]

        if errors:
            results.append(CheckResult(
                "config_valid",
                False,
                f"Configuration has {len(errors)} error(s)",
                "Run 'lucidshark validate' for details",
            ))
        elif warnings:
            results.append(CheckResult(
                "config_valid",
                True,
                f"Configuration valid ({len(warnings)} warning(s))",
            ))
        else:
            results.append(CheckResult(
                "config_valid",
                True,
                "Configuration is valid",
            ))

        return results

    def _check_tools(self, project_root: Path) -> List[CheckResult]:
        """Check tool availability.

        Args:
            project_root: Project root directory.

        Returns:
            List of check results.
        """
        results: List[CheckResult] = []
        home = get_lucidshark_home()
        paths = LucidsharkPaths(home)

        # Check scanner plugins (security tools)
        scanner_plugins = discover_scanner_plugins()

        for name, plugin_class in sorted(scanner_plugins.items()):
            try:
                plugin = plugin_class()
                binary_dir = paths.plugin_bin_dir(name, plugin.get_version())
                binary_path = binary_dir / name

                status = validate_binary(binary_path)
                if status == ToolStatus.PRESENT:
                    results.append(CheckResult(
                        f"tool_{name}",
                        True,
                        f"{name} v{plugin.get_version()} installed",
                    ))
                else:
                    results.append(CheckResult(
                        f"tool_{name}",
                        False,
                        f"{name} not installed",
                        f"Will be downloaded on first scan using --{self._get_domain_flag(name)}",
                    ))
            except Exception as e:
                results.append(CheckResult(
                    f"tool_{name}",
                    False,
                    f"{name} plugin error: {e}",
                ))

        # Check common linters/type checkers that should be pip-installed
        pip_tools = [
            ("ruff", "linting"),
            ("mypy", "type-checking"),
            ("pyright", "type-checking"),
        ]

        for tool, domain in pip_tools:
            if self._check_pip_tool(tool):
                results.append(CheckResult(
                    f"tool_{tool}",
                    True,
                    f"{tool} available in environment",
                ))
            # Don't report missing pip tools as errors - they're optional

        return results

    def _check_environment(self) -> List[CheckResult]:
        """Check environment requirements.

        Returns:
            List of check results.
        """
        results: List[CheckResult] = []
        platform_info = get_platform_info()

        # Python version
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if sys.version_info >= (3, 10):
            results.append(CheckResult(
                "python_version",
                True,
                f"Python {py_version}",
            ))
        else:
            results.append(CheckResult(
                "python_version",
                False,
                f"Python {py_version} (requires 3.10+)",
                "Upgrade to Python 3.10 or later",
            ))

        # Platform
        results.append(CheckResult(
            "platform",
            True,
            f"Platform: {platform_info.os}-{platform_info.arch}",
        ))

        # Git repository
        if self._is_git_repo():
            results.append(CheckResult(
                "git_repo",
                True,
                "Git repository detected",
            ))
        else:
            results.append(CheckResult(
                "git_repo",
                False,
                "Not a git repository",
                "LucidShark works best in a git repository for change detection",
            ))

        return results

    def _check_integrations(self) -> List[CheckResult]:
        """Check AI tool integrations.

        Returns:
            List of check results.
        """
        results: List[CheckResult] = []
        project_root = Path.cwd()

        # Check Claude Code MCP config (project .mcp.json, project .claude/, global)
        claude_result = self._check_mcp_config(
            name="claude_code_mcp",
            display_name="Claude Code",
            global_config=Path.home() / ".claude" / "mcp_servers.json",
            project_config=project_root / ".claude" / "mcp_servers.json",
            project_mcp_json=project_root / ".mcp.json",
            init_command="lucidshark init --claude-code",
            report_if_missing=True,
        )
        if claude_result is not None:
            results.append(claude_result)

        # Check Cursor MCP config (global and project-level)
        cursor_result = self._check_mcp_config(
            name="cursor_mcp",
            display_name="Cursor",
            global_config=Path.home() / ".cursor" / "mcp.json",
            project_config=project_root / ".cursor" / "mcp.json",
            init_command="lucidshark init --cursor",
            report_if_missing=False,  # Don't report Cursor as missing if not installed
        )
        if cursor_result is not None:
            results.append(cursor_result)

        return results

    def _check_mcp_config(
        self,
        name: str,
        display_name: str,
        global_config: Path,
        project_config: Path,
        init_command: str,
        report_if_missing: bool = True,
        project_mcp_json: Path | None = None,
    ) -> CheckResult | None:
        """Check MCP configuration for an AI tool.

        Checks project .mcp.json, project-level, and global configurations.

        Args:
            name: Check result name identifier.
            display_name: Human-readable tool name.
            global_config: Path to global MCP config file.
            project_config: Path to project-level MCP config file.
            init_command: Command to run for initialization.
            report_if_missing: Whether to report if tool is not installed.
            project_mcp_json: Optional path to project .mcp.json (Claude Code).

        Returns:
            CheckResult or None if tool not installed and report_if_missing is False.
        """
        import json

        configs_to_check = []
        if project_mcp_json is not None:
            configs_to_check.append((project_mcp_json, "project"))
        configs_to_check.extend([
            (project_config, "project"),
            (global_config, "global"),
        ])

        for config_path, level in configs_to_check:
            if config_path.exists():
                try:
                    with open(config_path) as f:
                        config_data = json.load(f)
                    mcp_servers = config_data.get("mcpServers", {})
                    if "lucidshark" in mcp_servers:
                        return CheckResult(
                            name,
                            True,
                            f"{display_name} MCP configured ({level})",
                        )
                except Exception:
                    return CheckResult(
                        name,
                        False,
                        f"Could not read {display_name} config ({level})",
                        f"Run '{init_command}'",
                    )

        # Check if any config file exists (tool is installed but not configured)
        any_config_exists = (
            global_config.exists()
            or project_config.exists()
            or (project_mcp_json is not None and project_mcp_json.exists())
        )

        if any_config_exists:
            return CheckResult(
                name,
                False,
                f"{display_name} MCP not configured",
                f"Run '{init_command}'",
            )

        # Tool not installed
        if report_if_missing:
            return CheckResult(
                name,
                False,
                f"{display_name} not installed or not configured",
                f"Install {display_name}, then run '{init_command}'",
            )

        return None

    def _print_results(self, results: List[CheckResult]) -> None:
        """Print check results grouped by category.

        Args:
            results: List of check results.
        """
        categories = {
            "Configuration": ["config_file", "config_valid"],
            "Tools": [r.name for r in results if r.name.startswith("tool_")],
            "Environment": ["python_version", "platform", "git_repo"],
            "Integrations": ["claude_code_mcp", "cursor_mcp"],
        }

        for category, keys in categories.items():
            category_results = [r for r in results if r.name in keys]
            if not category_results:
                continue

            print(f"{category}")
            for result in category_results:
                status = result.status_icon
                print(f"  {status} {result.message}")
                if not result.passed and result.hint:
                    print(f"       -> {result.hint}")
            print()

    def _is_git_repo(self) -> bool:
        """Check if current directory is a git repository.

        Returns:
            True if git repo, False otherwise.
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_pip_tool(self, tool: str) -> bool:
        """Check if a pip-installed tool is available.

        Args:
            tool: Tool name to check.

        Returns:
            True if available, False otherwise.
        """
        try:
            result = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_domain_flag(self, scanner_name: str) -> str:
        """Get the CLI flag for a scanner's domain.

        Args:
            scanner_name: Scanner plugin name.

        Returns:
            CLI flag for the scanner's primary domain.
        """
        domain_mapping = {
            "trivy": "sca",
            "opengrep": "sast",
            "checkov": "iac",
        }
        return domain_mapping.get(scanner_name, "all")
