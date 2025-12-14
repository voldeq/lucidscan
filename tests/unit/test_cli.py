"""Tests for CLI functionality."""

from __future__ import annotations

import argparse
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

        # Status flag
        assert any(a.option_strings and "--status" in a.option_strings for a in parser._actions)


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

    def test_main_version_shows_version(self, capsys) -> None:
        exit_code = cli.main(["--version"])
        captured = capsys.readouterr()
        assert exit_code == 0
        # Should output a version string
        assert captured.out.strip()  # Non-empty output


class TestStatusFlag:
    """Tests for --status CLI flag (tool validation)."""

    def test_status_flag_exists(self) -> None:
        parser = cli.build_parser()
        assert any(
            a.option_strings and "--status" in a.option_strings
            for a in parser._actions
        )

    def test_status_shows_tool_validation(self, capsys, tmp_path: Path) -> None:
        """Test that --status shows scanner plugin status."""
        home = tmp_path / ".lucidscan"
        home.mkdir(parents=True)

        with patch("lucidscan.cli.get_lucidscan_home", return_value=home):
            with patch("lucidscan.cli.validate_tools") as mock_validate:
                from lucidscan.bootstrap.validation import ToolValidationResult

                mock_validate.return_value = ToolValidationResult(
                    trivy=ToolStatus.PRESENT,
                    opengrep=ToolStatus.MISSING,
                    checkov=ToolStatus.NOT_EXECUTABLE,
                )

                exit_code = cli.main(["--status"])

                captured = capsys.readouterr()
                assert "trivy" in captured.out.lower()
                assert "opengrep" in captured.out.lower()
                assert "checkov" in captured.out.lower()

    def test_status_shows_platform_info(self, capsys, tmp_path: Path) -> None:
        """Test that --status shows platform information."""
        home = tmp_path / ".lucidscan"
        home.mkdir(parents=True)

        with patch("lucidscan.cli.get_lucidscan_home", return_value=home):
            exit_code = cli.main(["--status"])

            captured = capsys.readouterr()
            assert "platform" in captured.out.lower()
            assert exit_code == 0


class TestExitCodes:
    """Tests for correct exit codes per Section 14."""

    def test_exit_code_0_on_version(self) -> None:
        exit_code = cli.main(["--version"])
        assert exit_code == 0

    def test_exit_code_0_on_help(self) -> None:
        exit_code = cli.main(["--help"])
        assert exit_code == 0

    def test_exit_code_0_on_status(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        home.mkdir(parents=True)

        with patch("lucidscan.cli.get_lucidscan_home", return_value=home):
            exit_code = cli.main(["--status"])
            assert exit_code == 0
