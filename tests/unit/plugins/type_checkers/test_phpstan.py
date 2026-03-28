"""Unit tests for PHPStan type checker plugin.

These tests mock subprocess calls to test the parsing logic without
requiring actual PHPStan installation.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.type_checkers.phpstan import (
    PhpstanChecker,
    _find_phpstan,
)


def make_completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestPhpstanChecker:
    """Unit tests for PhpstanChecker."""

    def test_name(self) -> None:
        checker = PhpstanChecker()
        assert checker.name == "phpstan"

    def test_languages(self) -> None:
        checker = PhpstanChecker()
        assert checker.languages == ["php"]

    def test_domain(self) -> None:
        checker = PhpstanChecker()
        assert checker.domain == ToolDomain.TYPE_CHECKING

    def test_supports_strict_mode(self) -> None:
        checker = PhpstanChecker()
        assert checker.supports_strict_mode is True

    def test_ensure_binary_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            phpstan_path = vendor_bin / "phpstan"
            phpstan_path.touch()

            checker = PhpstanChecker(project_root=tmpdir_path)
            binary = checker.ensure_binary()
            assert binary == phpstan_path

    def test_ensure_binary_system_path(self) -> None:
        checker = PhpstanChecker()
        with patch("shutil.which", return_value="/usr/local/bin/phpstan"):
            binary = checker.ensure_binary()
            assert binary == Path("/usr/local/bin/phpstan")

    def test_ensure_binary_not_found(self) -> None:
        checker = PhpstanChecker()
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError) as exc_info:
                checker.ensure_binary()
            assert "PHPStan is not installed" in str(exc_info.value)

    def test_check_no_binary(self) -> None:
        checker = PhpstanChecker()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                checker, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                issues = checker.check(context)
                assert issues == []

    def test_check_success(self) -> None:
        checker = PhpstanChecker()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            phpstan_output = json.dumps(
                {
                    "totals": {"errors": 0, "file_errors": 1},
                    "files": {
                        "/test/src/Foo.php": {
                            "errors": 1,
                            "messages": [
                                {
                                    "message": "Parameter $bar of method Foo::baz() has no type specified.",
                                    "line": 15,
                                    "ignorable": True,
                                    "identifier": "missingType.parameter",
                                }
                            ],
                        }
                    },
                    "errors": [],
                }
            )

            mock_result = make_completed_process(returncode=1, stdout=phpstan_output)

            with patch.object(
                checker, "ensure_binary", return_value=Path("/usr/bin/phpstan")
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.phpstan.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = checker.check(context)
                    assert len(issues) == 1
                    assert issues[0].source_tool == "phpstan"
                    assert issues[0].domain == ToolDomain.TYPE_CHECKING
                    assert issues[0].line_start == 15
                    assert "missingType.parameter" in issues[0].title
                    assert issues[0].severity == Severity.HIGH

    def test_check_timeout(self) -> None:
        checker = PhpstanChecker()
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )
            with patch.object(
                checker, "ensure_binary", return_value=Path("/usr/bin/phpstan")
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.phpstan.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired("phpstan", 300),
                ):
                    issues = checker.check(context)
                    assert issues == []
                    assert len(context.tool_skips) == 1

    def test_check_general_errors(self) -> None:
        checker = PhpstanChecker()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            phpstan_output = json.dumps(
                {
                    "totals": {"errors": 1, "file_errors": 0},
                    "files": {},
                    "errors": ["Autoloader error: class not found"],
                }
            )

            mock_result = make_completed_process(returncode=1, stdout=phpstan_output)

            with patch.object(
                checker, "ensure_binary", return_value=Path("/usr/bin/phpstan")
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.phpstan.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = checker.check(context)
                    assert len(issues) == 1
                    assert issues[0].rule_id == "general_error"


class TestPhpstanOutputParsing:
    """Tests for phpstan output parsing."""

    def test_parse_empty_output(self) -> None:
        checker = PhpstanChecker()
        issues = checker._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_invalid_json(self) -> None:
        checker = PhpstanChecker()
        issues = checker._parse_output("not json", Path("/project"))
        assert issues == []

    def test_parse_no_errors(self) -> None:
        checker = PhpstanChecker()
        output = json.dumps(
            {
                "totals": {"errors": 0, "file_errors": 0},
                "files": {},
                "errors": [],
            }
        )
        issues = checker._parse_output(output, Path("/project"))
        assert issues == []

    def test_parse_multiple_files(self) -> None:
        checker = PhpstanChecker()
        output = json.dumps(
            {
                "files": {
                    "/a.php": {
                        "messages": [
                            {"message": "Error 1", "line": 1, "identifier": "id1"}
                        ]
                    },
                    "/b.php": {
                        "messages": [
                            {"message": "Error 2", "line": 5, "identifier": "id2"}
                        ]
                    },
                },
                "errors": [],
            }
        )

        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 2

    def test_parse_deduplicates(self) -> None:
        checker = PhpstanChecker()
        output = json.dumps(
            {
                "files": {
                    "/a.php": {
                        "messages": [
                            {"message": "Same error", "line": 1, "identifier": "id1"},
                            {"message": "Same error", "line": 1, "identifier": "id1"},
                        ]
                    }
                },
                "errors": [],
            }
        )

        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1


class TestPhpstanIssueId:
    """Tests for issue ID generation."""

    def test_deterministic(self) -> None:
        checker = PhpstanChecker()
        id1 = checker._generate_issue_id("rule1", "file.php", 10, "msg")
        id2 = checker._generate_issue_id("rule1", "file.php", 10, "msg")
        assert id1 == id2

    def test_different_inputs(self) -> None:
        checker = PhpstanChecker()
        id1 = checker._generate_issue_id("rule1", "file.php", 10, "msg")
        id2 = checker._generate_issue_id("rule2", "file.php", 10, "msg")
        assert id1 != id2

    def test_prefix(self) -> None:
        checker = PhpstanChecker()
        issue_id = checker._generate_issue_id("rule1", "file.php", 10, "msg")
        assert issue_id.startswith("phpstan-")


class TestFindPhpstan:
    """Tests for _find_phpstan helper."""

    def test_find_in_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            vendor_bin = tmpdir_path / "vendor" / "bin"
            vendor_bin.mkdir(parents=True)
            (vendor_bin / "phpstan").touch()

            result = _find_phpstan(tmpdir_path)
            assert result == vendor_bin / "phpstan"

    def test_find_in_path(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/phpstan"):
            result = _find_phpstan()
            assert result == Path("/usr/bin/phpstan")

    def test_not_found(self) -> None:
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError):
                _find_phpstan()
