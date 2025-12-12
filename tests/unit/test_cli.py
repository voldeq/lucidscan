"""Tests for CLI functionality."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import lucidscan.cli as cli
from lucidscan.bootstrap.paths import LucidscanPaths
from lucidscan.bootstrap.validation import ToolStatus


class TestBuildParser:
    """Tests for CLI argument parser."""

    def test_build_parser_includes_core_flags(self) -> None:
        parser = cli.build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

        # Global flags
        for flag in ["--version", "--debug", "--verbose", "--quiet", "--format"]:
            assert any(a.option_strings and flag in a.option_strings for a in parser._actions)

        # Scanner flags
        for flag in ["--sca", "--container", "--iac", "--sast", "--all"]:
            assert any(a.option_strings and flag in a.option_strings for a in parser._actions)

        # Bootstrap flags (Phase 1)
        for flag in ["--bootstrap", "--update-tools", "--status"]:
            assert any(a.option_strings and flag in a.option_strings for a in parser._actions)


class TestMainCommand:
    """Tests for main CLI entry point."""

    def test_main_help_exits_successfully(self, capsys) -> None:
        exit_code = cli.main(["--help"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "usage:" in captured.out.lower()

    def test_main_scanner_flags_are_stubbed(self, capsys) -> None:
        exit_code = cli.main(["--sca"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "not implemented yet" in captured.out.lower()


class TestBootstrapFlag:
    """Tests for --bootstrap CLI flag."""

    def test_bootstrap_flag_exists(self) -> None:
        parser = cli.build_parser()
        assert any(
            a.option_strings and "--bootstrap" in a.option_strings
            for a in parser._actions
        )

    def test_bootstrap_runs_bundle_manager(self, capsys, tmp_path: Path) -> None:
        with patch("lucidscan.cli.get_lucidscan_home", return_value=tmp_path / ".lucidscan"):
            with patch("lucidscan.cli.BundleManager") as MockBundleManager:
                mock_manager = MagicMock()
                MockBundleManager.return_value = mock_manager

                exit_code = cli.main(["--bootstrap"])

                mock_manager.bootstrap.assert_called_once_with(force=False)
                assert exit_code == 0

    def test_bootstrap_reports_error_on_failure(self, capsys, tmp_path: Path) -> None:
        from lucidscan.bootstrap.bundle import BundleError

        with patch("lucidscan.cli.get_lucidscan_home", return_value=tmp_path / ".lucidscan"):
            with patch("lucidscan.cli.BundleManager") as MockBundleManager:
                mock_manager = MagicMock()
                mock_manager.bootstrap.side_effect = BundleError("Download failed")
                MockBundleManager.return_value = mock_manager

                exit_code = cli.main(["--bootstrap"])

                captured = capsys.readouterr()
                assert exit_code == 4  # Tool bootstrap failure
                assert "download failed" in captured.err.lower() or "bootstrap failed" in captured.err.lower()


class TestUpdateToolsFlag:
    """Tests for --update-tools CLI flag."""

    def test_update_tools_flag_exists(self) -> None:
        parser = cli.build_parser()
        assert any(
            a.option_strings and "--update-tools" in a.option_strings
            for a in parser._actions
        )

    def test_update_tools_forces_bootstrap(self, capsys, tmp_path: Path) -> None:
        with patch("lucidscan.cli.get_lucidscan_home", return_value=tmp_path / ".lucidscan"):
            with patch("lucidscan.cli.BundleManager") as MockBundleManager:
                mock_manager = MagicMock()
                MockBundleManager.return_value = mock_manager

                exit_code = cli.main(["--update-tools"])

                mock_manager.bootstrap.assert_called_once_with(force=True)
                assert exit_code == 0


class TestStatusFlag:
    """Tests for --status CLI flag (tool validation)."""

    def test_status_flag_exists(self) -> None:
        parser = cli.build_parser()
        assert any(
            a.option_strings and "--status" in a.option_strings
            for a in parser._actions
        )

    def test_status_shows_tool_validation(self, capsys, tmp_path: Path) -> None:
        # Set up an initialized bundle (versions.json must exist)
        home = tmp_path / ".lucidscan"
        home.mkdir(parents=True)
        config_dir = home / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "versions.json").write_text('{"lucidscan": "0.1.0"}')

        with patch("lucidscan.cli.get_lucidscan_home", return_value=home):
            with patch("lucidscan.cli.validate_tools") as mock_validate:
                from lucidscan.bootstrap.validation import ToolValidationResult

                mock_validate.return_value = ToolValidationResult(
                    trivy=ToolStatus.PRESENT,
                    semgrep=ToolStatus.MISSING,
                    checkov=ToolStatus.NOT_EXECUTABLE,
                )

                exit_code = cli.main(["--status"])

                captured = capsys.readouterr()
                assert "trivy" in captured.out.lower()
                assert "semgrep" in captured.out.lower()
                assert "checkov" in captured.out.lower()


class TestExitCodes:
    """Tests for correct exit codes per Section 14."""

    def test_exit_code_0_on_success(self, tmp_path: Path) -> None:
        with patch("lucidscan.cli.get_lucidscan_home", return_value=tmp_path / ".lucidscan"):
            with patch("lucidscan.cli.BundleManager") as MockBundleManager:
                mock_manager = MagicMock()
                MockBundleManager.return_value = mock_manager

                exit_code = cli.main(["--bootstrap"])
                assert exit_code == 0

    def test_exit_code_4_on_bootstrap_failure(self, tmp_path: Path) -> None:
        from lucidscan.bootstrap.bundle import BundleError

        with patch("lucidscan.cli.get_lucidscan_home", return_value=tmp_path / ".lucidscan"):
            with patch("lucidscan.cli.BundleManager") as MockBundleManager:
                mock_manager = MagicMock()
                mock_manager.bootstrap.side_effect = BundleError("Failed")
                MockBundleManager.return_value = mock_manager

                exit_code = cli.main(["--bootstrap"])
                assert exit_code == 4
