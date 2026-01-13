"""Tests for validate command."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from lucidscan.cli.commands.validate import ValidateCommand
from lucidscan.cli.exit_codes import EXIT_ISSUES_FOUND, EXIT_INVALID_USAGE, EXIT_SUCCESS


class TestValidateCommand:
    """Tests for ValidateCommand."""

    def test_command_name(self) -> None:
        """Test command name property."""
        cmd = ValidateCommand()
        assert cmd.name == "validate"

    def test_valid_config_returns_success(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Test valid config returns exit code 0."""
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_on: high\nignore:\n  - tests/**\n")

        monkeypatch.chdir(tmp_path)
        cmd = ValidateCommand()
        args = Namespace(config=None)

        result = cmd.execute(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "valid" in captured.out.lower()

    def test_invalid_config_returns_issues_found(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Test config with errors returns exit code 1."""
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_on: 123\n")  # Wrong type

        monkeypatch.chdir(tmp_path)
        cmd = ValidateCommand()
        args = Namespace(config=None)

        result = cmd.execute(args)

        assert result == EXIT_ISSUES_FOUND
        captured = capsys.readouterr()
        assert "error" in captured.out.lower()

    def test_missing_config_returns_invalid_usage(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Test missing config file returns exit code 3."""
        monkeypatch.chdir(tmp_path)
        cmd = ValidateCommand()
        args = Namespace(config=None)

        result = cmd.execute(args)

        assert result == EXIT_INVALID_USAGE
        captured = capsys.readouterr()
        assert "no configuration file found" in captured.out.lower()

    def test_custom_config_path(self, tmp_path: Path, capsys) -> None:
        """Test can validate a custom config path."""
        config_file = tmp_path / "custom.yml"
        config_file.write_text("fail_on: high\n")

        cmd = ValidateCommand()
        args = Namespace(config=str(config_file))

        result = cmd.execute(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "valid" in captured.out.lower()

    def test_yaml_syntax_error(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Test YAML syntax errors are reported."""
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("invalid: yaml: content:\n  - bad")

        monkeypatch.chdir(tmp_path)
        cmd = ValidateCommand()
        args = Namespace(config=None)

        result = cmd.execute(args)

        assert result == EXIT_ISSUES_FOUND
        captured = capsys.readouterr()
        assert "error" in captured.out.lower()

    def test_warnings_dont_fail_validation(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Test that warnings alone don't cause validation failure."""
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("unknown_key: value\nfail_on: high\n")  # Unknown key is just a warning

        monkeypatch.chdir(tmp_path)
        cmd = ValidateCommand()
        args = Namespace(config=None)

        result = cmd.execute(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "warning" in captured.out.lower()

    def test_typo_suggestion_shown(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """Test that typo suggestions are shown in output."""
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_ob: high\n")  # Typo: should be fail_on

        monkeypatch.chdir(tmp_path)
        cmd = ValidateCommand()
        args = Namespace(config=None)

        cmd.execute(args)

        captured = capsys.readouterr()
        assert "fail_on" in captured.out  # Suggestion should be shown

    def test_nonexistent_custom_path(self, tmp_path: Path, capsys) -> None:
        """Test nonexistent custom config path returns invalid usage."""
        cmd = ValidateCommand()
        args = Namespace(config=str(tmp_path / "nonexistent.yml"))

        result = cmd.execute(args)

        assert result == EXIT_INVALID_USAGE
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()
