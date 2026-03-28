"""Unit tests for PHP_CodeSniffer (phpcs) linter plugin.

These tests mock subprocess calls to test the parsing logic without
requiring actual phpcs installation.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.linters.phpcs import (
    PhpcsLinter,
    PHPCS_SEVERITY_MAP,
    PHP_EXTENSIONS,
    _find_phpcs,
    _find_phpcbf,
)


def make_completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestPhpcsLinter:
    """Unit tests for PhpcsLinter."""

    def test_name(self) -> None:
        linter = PhpcsLinter()
        assert linter.name == "phpcs"

    def test_languages(self) -> None:
        linter = PhpcsLinter()
        assert linter.languages == ["php"]

    def test_supports_fix(self) -> None:
        linter = PhpcsLinter()
        assert linter.supports_fix is True

    def test_domain(self) -> None:
        linter = PhpcsLinter()
        assert linter.domain == ToolDomain.LINTING

    def test_get_version_success(self) -> None:
        linter = PhpcsLinter()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "3.7.2"

        with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/phpcs")):
            with patch("subprocess.run", return_value=mock_result):
                version = linter.get_version()
                assert version == "3.7.2"

    def test_get_version_failure(self) -> None:
        linter = PhpcsLinter()
        with patch.object(linter, "ensure_binary", side_effect=FileNotFoundError()):
            version = linter.get_version()
            assert version == "unknown"

    def test_ensure_binary_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            phpcs_path = vendor_bin / "phpcs"
            phpcs_path.touch()

            linter = PhpcsLinter(project_root=tmpdir_path)
            binary = linter.ensure_binary()
            assert binary == phpcs_path

    def test_ensure_binary_system_path(self) -> None:
        linter = PhpcsLinter()
        with patch("shutil.which", return_value="/usr/local/bin/phpcs"):
            binary = linter.ensure_binary()
            assert binary == Path("/usr/local/bin/phpcs")

    def test_ensure_binary_not_found(self) -> None:
        linter = PhpcsLinter()
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError) as exc_info:
                linter.ensure_binary()
            assert "PHP_CodeSniffer is not installed" in str(exc_info.value)

    def test_lint_no_binary(self) -> None:
        linter = PhpcsLinter()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                linter, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                issues = linter.lint(context)
                assert issues == []

    def test_lint_success(self) -> None:
        linter = PhpcsLinter()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            phpcs_output = json.dumps(
                {
                    "totals": {"errors": 1, "warnings": 0, "fixable": 1},
                    "files": {
                        "/test/src/File.php": {
                            "errors": 1,
                            "warnings": 0,
                            "messages": [
                                {
                                    "message": "Line exceeds 120 characters",
                                    "source": "Generic.Files.LineLength.TooLong",
                                    "severity": 5,
                                    "fixable": False,
                                    "type": "WARNING",
                                    "line": 42,
                                    "column": 121,
                                }
                            ],
                        }
                    },
                }
            )

            mock_result = make_completed_process(returncode=1, stdout=phpcs_output)

            with patch.object(
                linter, "ensure_binary", return_value=Path("/usr/bin/phpcs")
            ):
                with patch(
                    "lucidshark.plugins.linters.base.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = linter.lint(context)
                    assert len(issues) == 1
                    assert issues[0].source_tool == "phpcs"
                    assert issues[0].domain == ToolDomain.LINTING
                    assert "Generic.Files.LineLength.TooLong" in issues[0].title
                    assert issues[0].line_start == 42
                    assert issues[0].severity == Severity.MEDIUM

    def test_lint_timeout(self) -> None:
        linter = PhpcsLinter()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                linter, "ensure_binary", return_value=Path("/usr/bin/phpcs")
            ):
                with patch(
                    "lucidshark.plugins.linters.base.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired("phpcs", 300),
                ):
                    issues = linter.lint(context)
                    assert issues == []

    def test_lint_error_severity(self) -> None:
        linter = PhpcsLinter()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            phpcs_output = json.dumps(
                {
                    "totals": {"errors": 1, "warnings": 0},
                    "files": {
                        "/test/File.php": {
                            "messages": [
                                {
                                    "message": "Missing doc comment",
                                    "source": "PSR12.Methods.Missing",
                                    "type": "ERROR",
                                    "line": 5,
                                    "column": 1,
                                    "fixable": True,
                                }
                            ]
                        }
                    },
                }
            )

            mock_result = make_completed_process(returncode=1, stdout=phpcs_output)

            with patch.object(
                linter, "ensure_binary", return_value=Path("/usr/bin/phpcs")
            ):
                with patch(
                    "lucidshark.plugins.linters.base.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = linter.lint(context)
                    assert len(issues) == 1
                    assert issues[0].severity == Severity.HIGH
                    assert issues[0].fixable is True


class TestPhpcsOutputParsing:
    """Tests for phpcs output parsing."""

    def test_parse_empty_output(self) -> None:
        linter = PhpcsLinter()
        issues = linter._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_invalid_json(self) -> None:
        linter = PhpcsLinter()
        issues = linter._parse_output("not json", Path("/project"))
        assert issues == []

    def test_parse_no_files(self) -> None:
        linter = PhpcsLinter()
        output = json.dumps({"totals": {}, "files": {}})
        issues = linter._parse_output(output, Path("/project"))
        assert issues == []

    def test_parse_multiple_files(self) -> None:
        linter = PhpcsLinter()
        output = json.dumps(
            {
                "files": {
                    "/a.php": {
                        "messages": [
                            {
                                "message": "Error 1",
                                "source": "rule1",
                                "type": "ERROR",
                                "line": 1,
                                "column": 1,
                            }
                        ]
                    },
                    "/b.php": {
                        "messages": [
                            {
                                "message": "Warning 1",
                                "source": "rule2",
                                "type": "WARNING",
                                "line": 5,
                                "column": 1,
                            }
                        ]
                    },
                }
            }
        )

        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 2

    def test_parse_deduplicates_issues(self) -> None:
        linter = PhpcsLinter()
        output = json.dumps(
            {
                "files": {
                    "/a.php": {
                        "messages": [
                            {
                                "message": "Same error",
                                "source": "rule1",
                                "type": "ERROR",
                                "line": 1,
                                "column": 1,
                            },
                            {
                                "message": "Same error",
                                "source": "rule1",
                                "type": "ERROR",
                                "line": 1,
                                "column": 1,
                            },
                        ]
                    }
                }
            }
        )

        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1


class TestPhpcsFix:
    """Tests for phpcs fix functionality."""

    def test_fix_no_phpcbf(self) -> None:
        linter = PhpcsLinter()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch(
                "lucidshark.plugins.linters.phpcs._find_phpcbf", return_value=None
            ):
                result = linter.fix(context)
                assert result.issues_fixed == 0


class TestIssueIdGeneration:
    """Tests for issue ID generation."""

    def test_deterministic(self) -> None:
        linter = PhpcsLinter()
        id1 = linter._generate_issue_id("rule1", "file.php", 10, 5, "msg")
        id2 = linter._generate_issue_id("rule1", "file.php", 10, 5, "msg")
        assert id1 == id2

    def test_different_inputs(self) -> None:
        linter = PhpcsLinter()
        id1 = linter._generate_issue_id("rule1", "file.php", 10, 5, "msg")
        id2 = linter._generate_issue_id("rule2", "file.php", 10, 5, "msg")
        assert id1 != id2

    def test_prefix_with_rule(self) -> None:
        linter = PhpcsLinter()
        issue_id = linter._generate_issue_id("PSR12.Rule", "file.php", 10, 5, "msg")
        assert issue_id.startswith("phpcs-PSR12.Rule-")

    def test_prefix_without_rule(self) -> None:
        linter = PhpcsLinter()
        issue_id = linter._generate_issue_id("", "file.php", 10, 5, "msg")
        assert issue_id.startswith("phpcs-")


class TestSeverityMapping:
    """Tests for phpcs severity mapping."""

    def test_error_maps_to_high(self) -> None:
        assert PHPCS_SEVERITY_MAP["ERROR"] == Severity.HIGH

    def test_warning_maps_to_medium(self) -> None:
        assert PHPCS_SEVERITY_MAP["WARNING"] == Severity.MEDIUM


class TestPhpExtensions:
    """Tests for PHP_EXTENSIONS constant."""

    def test_php_included(self) -> None:
        assert ".php" in PHP_EXTENSIONS

    def test_non_php_not_included(self) -> None:
        assert ".py" not in PHP_EXTENSIONS
        assert ".js" not in PHP_EXTENSIONS


class TestFindPhpcs:
    """Tests for _find_phpcs helper."""

    def test_find_in_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            (vendor_bin / "phpcs").touch()

            result = _find_phpcs(tmpdir_path)
            assert result == vendor_bin / "phpcs"

    def test_find_in_path(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/phpcs"):
            result = _find_phpcs()
            assert result == Path("/usr/bin/phpcs")

    def test_not_found(self) -> None:
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError):
                _find_phpcs()


class TestFindPhpcbf:
    """Tests for _find_phpcbf helper."""

    def test_find_in_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            (vendor_bin / "phpcbf").touch()

            result = _find_phpcbf(tmpdir_path)
            assert result == vendor_bin / "phpcbf"

    def test_not_found(self) -> None:
        with patch("shutil.which", return_value=None):
            result = _find_phpcbf()
            assert result is None
