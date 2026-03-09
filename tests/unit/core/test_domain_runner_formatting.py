"""Unit tests for DomainRunner.run_formatting method."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from lucidshark.config.models import LucidSharkConfig
from lucidshark.core.domain_runner import DomainRunner
from lucidshark.core.models import ToolDomain, UnifiedIssue


def _make_runner(tmp_path: Path) -> DomainRunner:
    """Create a DomainRunner with default config."""
    config = LucidSharkConfig()
    return DomainRunner(tmp_path, config)


def _make_context(tmp_path: Path) -> Any:
    """Create a minimal ScanContext-like mock."""
    ctx = MagicMock()
    ctx.project_root = tmp_path
    ctx.ignore_patterns = MagicMock()
    return ctx


def _completed(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Build a CompletedProcess for testing."""
    return subprocess.CompletedProcess(
        args="test",
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _make_mock_issue(**kwargs: Any) -> UnifiedIssue:
    """Create a mock UnifiedIssue with defaults."""
    defaults = {
        "id": "format-issue",
        "domain": ToolDomain.FORMATTING,
        "file": "test.py",
        "line": 1,
        "description": "formatting issue",
        "tool": "mock_formatter",
    }
    defaults.update(kwargs)
    issue = MagicMock(spec=UnifiedIssue)
    for k, v in defaults.items():
        setattr(issue, k, v)
    return issue


class TestRunFormatting:
    """Tests for DomainRunner.run_formatting."""

    def test_fix_false_calls_check_only(self, tmp_path: Path) -> None:
        """With fix=False, plugins only call check(), not fix()."""
        runner = _make_runner(tmp_path)
        context = _make_context(tmp_path)

        mock_issue = _make_mock_issue()
        mock_plugin = MagicMock()
        mock_plugin.return_value.supports_fix = True
        mock_plugin.return_value.check.return_value = [mock_issue]

        with (
            patch(
                "lucidshark.plugins.formatters.discover_formatter_plugins"
            ) as mock_discover,
            patch(
                "lucidshark.core.domain_runner.filter_plugins_by_config"
            ) as mock_filter,
        ):
            mock_discover.return_value = {"mock_fmt": mock_plugin}
            mock_filter.return_value = {"mock_fmt": mock_plugin}
            issues = runner.run_formatting(context, fix=False)

        assert len(issues) == 1
        assert issues[0] is mock_issue
        mock_plugin.return_value.check.assert_called_once_with(context)
        mock_plugin.return_value.fix.assert_not_called()

    def test_fix_true_calls_fix_then_check(self, tmp_path: Path) -> None:
        """With fix=True and supports_fix=True, calls fix() then check()."""
        runner = _make_runner(tmp_path)
        context = _make_context(tmp_path)

        mock_issue = _make_mock_issue()
        mock_plugin = MagicMock()
        mock_plugin.return_value.supports_fix = True
        fix_result = MagicMock()
        fix_result.issues_fixed = 3
        fix_result.issues_remaining = 1
        mock_plugin.return_value.fix.return_value = fix_result
        mock_plugin.return_value.check.return_value = [mock_issue]

        with (
            patch(
                "lucidshark.plugins.formatters.discover_formatter_plugins"
            ) as mock_discover,
            patch(
                "lucidshark.core.domain_runner.filter_plugins_by_config"
            ) as mock_filter,
        ):
            mock_discover.return_value = {"mock_fmt": mock_plugin}
            mock_filter.return_value = {"mock_fmt": mock_plugin}
            issues = runner.run_formatting(context, fix=True)

        assert len(issues) == 1
        mock_plugin.return_value.fix.assert_called_once_with(context)
        mock_plugin.return_value.check.assert_called_once_with(context)

    def test_fix_true_but_plugin_does_not_support_fix(self, tmp_path: Path) -> None:
        """With fix=True but supports_fix=False, only calls check()."""
        runner = _make_runner(tmp_path)
        context = _make_context(tmp_path)

        mock_issue = _make_mock_issue()
        mock_plugin = MagicMock()
        mock_plugin.return_value.supports_fix = False
        mock_plugin.return_value.check.return_value = [mock_issue]

        with (
            patch(
                "lucidshark.plugins.formatters.discover_formatter_plugins"
            ) as mock_discover,
            patch(
                "lucidshark.core.domain_runner.filter_plugins_by_config"
            ) as mock_filter,
        ):
            mock_discover.return_value = {"mock_fmt": mock_plugin}
            mock_filter.return_value = {"mock_fmt": mock_plugin}
            issues = runner.run_formatting(context, fix=True)

        assert len(issues) == 1
        mock_plugin.return_value.fix.assert_not_called()
        mock_plugin.return_value.check.assert_called_once_with(context)

    def test_plugin_exception_is_caught_and_continues(self, tmp_path: Path) -> None:
        """When a plugin raises an exception, it is caught and the next plugin runs."""
        runner = _make_runner(tmp_path)
        context = _make_context(tmp_path)

        mock_issue = _make_mock_issue()

        bad_plugin = MagicMock()
        bad_plugin.return_value.supports_fix = False
        bad_plugin.return_value.check.side_effect = RuntimeError("plugin crashed")

        good_plugin = MagicMock()
        good_plugin.return_value.supports_fix = False
        good_plugin.return_value.check.return_value = [mock_issue]

        with (
            patch(
                "lucidshark.plugins.formatters.discover_formatter_plugins"
            ) as mock_discover,
            patch(
                "lucidshark.core.domain_runner.filter_plugins_by_config"
            ) as mock_filter,
        ):
            plugins = {"bad_fmt": bad_plugin, "good_fmt": good_plugin}
            mock_discover.return_value = plugins
            mock_filter.return_value = plugins
            issues = runner.run_formatting(context, fix=False)

        # The good plugin's issue should still be collected
        assert len(issues) == 1
        assert issues[0] is mock_issue

    def test_custom_command_runs_shell_command(self, tmp_path: Path) -> None:
        """With command set, runs shell command instead of discovering plugins."""
        runner = _make_runner(tmp_path)
        context = _make_context(tmp_path)

        with (
            patch("lucidshark.core.domain_runner.subprocess.run") as mock_run,
            patch(
                "lucidshark.plugins.formatters.discover_formatter_plugins"
            ) as mock_discover,
        ):
            mock_run.return_value = _completed(returncode=0, stdout="OK")
            issues = runner.run_formatting(context, command="fmt --check .")

        assert issues == []
        mock_run.assert_called()
        mock_discover.assert_not_called()

    def test_no_formatters_discovered_returns_empty(self, tmp_path: Path) -> None:
        """When no formatter plugins are discovered, returns empty list."""
        runner = _make_runner(tmp_path)
        context = _make_context(tmp_path)

        with patch(
            "lucidshark.plugins.formatters.discover_formatter_plugins"
        ) as mock_discover:
            mock_discover.return_value = {}
            issues = runner.run_formatting(context, fix=False)

        assert issues == []
