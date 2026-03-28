"""Unit tests for PHP-CS-Fixer formatter plugin.

These tests mock subprocess calls to test the parsing logic without
requiring actual PHP-CS-Fixer installation.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.formatters.php_cs_fixer import (
    PhpCsFixerFormatter,
    PHP_EXTENSIONS,
    _find_php_cs_fixer,
)


def make_completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestPhpCsFixerFormatter:
    """Unit tests for PhpCsFixerFormatter."""

    def test_name(self) -> None:
        formatter = PhpCsFixerFormatter()
        assert formatter.name == "php_cs_fixer"

    def test_languages(self) -> None:
        formatter = PhpCsFixerFormatter()
        assert formatter.languages == ["php"]

    def test_domain(self) -> None:
        formatter = PhpCsFixerFormatter()
        assert formatter.domain == ToolDomain.FORMATTING

    def test_supports_fix(self) -> None:
        formatter = PhpCsFixerFormatter()
        assert formatter.supports_fix is True

    def test_ensure_binary_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            fixer_path = vendor_bin / "php-cs-fixer"
            fixer_path.touch()

            formatter = PhpCsFixerFormatter(project_root=tmpdir_path)
            binary = formatter.ensure_binary()
            assert binary == fixer_path

    def test_ensure_binary_system_path(self) -> None:
        formatter = PhpCsFixerFormatter()
        with patch("shutil.which", return_value="/usr/local/bin/php-cs-fixer"):
            binary = formatter.ensure_binary()
            assert binary == Path("/usr/local/bin/php-cs-fixer")

    def test_ensure_binary_not_found(self) -> None:
        formatter = PhpCsFixerFormatter()
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError) as exc_info:
                formatter.ensure_binary()
            assert "PHP-CS-Fixer is not installed" in str(exc_info.value)

    def test_check_no_binary(self) -> None:
        formatter = PhpCsFixerFormatter()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_success(self) -> None:
        formatter = PhpCsFixerFormatter()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            fixer_output = json.dumps(
                {
                    "files": [
                        {
                            "name": "src/Foo.php",
                            "appliedFixers": ["braces", "line_ending"],
                        }
                    ]
                }
            )

            mock_result = make_completed_process(returncode=8, stdout=fixer_output)

            with patch.object(
                formatter, "ensure_binary", return_value=Path("/usr/bin/php-cs-fixer")
            ):
                with patch(
                    "lucidshark.plugins.formatters.php_cs_fixer.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = formatter.check(context)
                    assert len(issues) == 1
                    assert issues[0].source_tool == "php_cs_fixer"
                    assert issues[0].domain == ToolDomain.FORMATTING
                    assert issues[0].severity == Severity.LOW
                    assert "Foo.php" in issues[0].title
                    assert issues[0].fixable is True

    def test_check_no_issues(self) -> None:
        formatter = PhpCsFixerFormatter()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            fixer_output = json.dumps({"files": []})
            mock_result = make_completed_process(returncode=0, stdout=fixer_output)

            with patch.object(
                formatter, "ensure_binary", return_value=Path("/usr/bin/php-cs-fixer")
            ):
                with patch(
                    "lucidshark.plugins.formatters.php_cs_fixer.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = formatter.check(context)
                    assert issues == []

    def test_check_timeout(self) -> None:
        formatter = PhpCsFixerFormatter()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                formatter, "ensure_binary", return_value=Path("/usr/bin/php-cs-fixer")
            ):
                with patch(
                    "lucidshark.plugins.formatters.php_cs_fixer.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired("php-cs-fixer", 120),
                ):
                    issues = formatter.check(context)
                    assert issues == []
                    assert len(context.tool_skips) == 1


class TestPhpCsFixerOutputParsing:
    """Tests for php-cs-fixer output parsing."""

    def test_parse_empty_output(self) -> None:
        formatter = PhpCsFixerFormatter()
        issues = formatter._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_invalid_json(self) -> None:
        formatter = PhpCsFixerFormatter()
        issues = formatter._parse_output("not json", Path("/project"))
        assert issues == []

    def test_parse_no_files(self) -> None:
        formatter = PhpCsFixerFormatter()
        output = json.dumps({"files": []})
        issues = formatter._parse_output(output, Path("/project"))
        assert issues == []

    def test_parse_multiple_files(self) -> None:
        formatter = PhpCsFixerFormatter()
        output = json.dumps(
            {
                "files": [
                    {"name": "src/Foo.php", "appliedFixers": ["braces"]},
                    {"name": "src/Bar.php", "appliedFixers": ["line_ending", "spaces"]},
                ]
            }
        )

        issues = formatter._parse_output(output, Path("/project"))
        assert len(issues) == 2
        assert all(i.domain == ToolDomain.FORMATTING for i in issues)
        assert all(i.severity == Severity.LOW for i in issues)
        assert all(i.fixable is True for i in issues)

    def test_parse_includes_fixers_in_description(self) -> None:
        formatter = PhpCsFixerFormatter()
        output = json.dumps(
            {
                "files": [
                    {"name": "src/Foo.php", "appliedFixers": ["braces", "line_ending"]},
                ]
            }
        )

        issues = formatter._parse_output(output, Path("/project"))
        assert "braces" in issues[0].description
        assert "line_ending" in issues[0].description

    def test_parse_relative_path_resolution(self) -> None:
        formatter = PhpCsFixerFormatter()
        output = json.dumps(
            {
                "files": [
                    {"name": "src/Foo.php", "appliedFixers": ["braces"]},
                ]
            }
        )

        issues = formatter._parse_output(output, Path("/project"))
        assert issues[0].file_path == Path("/project/src/Foo.php")


class TestPhpCsFixerFix:
    """Tests for php-cs-fixer fix functionality."""

    def test_fix_no_binary(self) -> None:
        formatter = PhpCsFixerFormatter()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                result = formatter.fix(context)
                assert result.issues_fixed == 0

    def test_fix_success(self) -> None:
        formatter = PhpCsFixerFormatter()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            fix_output = json.dumps(
                {
                    "files": [
                        {"name": "src/Foo.php"},
                        {"name": "src/Bar.php"},
                    ]
                }
            )

            mock_result = make_completed_process(returncode=0, stdout=fix_output)

            with patch.object(
                formatter, "ensure_binary", return_value=Path("/usr/bin/php-cs-fixer")
            ):
                with patch(
                    "lucidshark.plugins.formatters.php_cs_fixer.run_with_streaming",
                    return_value=mock_result,
                ):
                    result = formatter.fix(context)
                    assert result.files_modified == 2
                    assert result.issues_fixed == 2


class TestFindPhpCsFixer:
    """Tests for _find_php_cs_fixer helper."""

    def test_find_in_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            (vendor_bin / "php-cs-fixer").touch()

            result = _find_php_cs_fixer(tmpdir_path)
            assert result == vendor_bin / "php-cs-fixer"

    def test_find_in_path(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/php-cs-fixer"):
            result = _find_php_cs_fixer()
            assert result == Path("/usr/bin/php-cs-fixer")

    def test_not_found(self) -> None:
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError):
                _find_php_cs_fixer()


class TestPhpExtensions:
    """Tests for PHP_EXTENSIONS constant."""

    def test_php_included(self) -> None:
        assert ".php" in PHP_EXTENSIONS

    def test_non_php_not_included(self) -> None:
        assert ".py" not in PHP_EXTENSIONS
        assert ".js" not in PHP_EXTENSIONS
