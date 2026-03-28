"""Unit tests for cppcheck type checker plugin."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.type_checkers.cppcheck import (
    CPPCHECK_SEVERITY,
    CppcheckChecker,
    _DIAG_RE,
)


def make_completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess:
    """Create a CompletedProcess for testing."""
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


FAKE_BINARY = Path("/usr/bin/cppcheck")


# ---------------------------------------------------------------------------
# CppcheckChecker properties
# ---------------------------------------------------------------------------


class TestCppcheckCheckerProperties:
    """Tests for CppcheckChecker basic properties."""

    def test_name(self) -> None:
        """Test plugin name."""
        checker = CppcheckChecker()
        assert checker.name == "cppcheck"

    def test_languages(self) -> None:
        """Test supported languages."""
        checker = CppcheckChecker()
        assert checker.languages == ["c"]

    def test_domain(self) -> None:
        """Test domain is TYPE_CHECKING."""
        checker = CppcheckChecker()
        assert checker.domain == ToolDomain.TYPE_CHECKING

    def test_supports_strict_mode(self) -> None:
        """Test strict mode is supported."""
        checker = CppcheckChecker()
        assert checker.supports_strict_mode is True

    def test_init_with_project_root(self) -> None:
        """Test initialization with project root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            checker = CppcheckChecker(project_root=Path(tmpdir))
            assert checker._project_root == Path(tmpdir)

    def test_get_version(self) -> None:
        """Test get_version delegates to get_cppcheck_version."""
        checker = CppcheckChecker()
        with patch(
            "lucidshark.plugins.type_checkers.cppcheck.get_cppcheck_version",
            return_value="Cppcheck 2.13",
        ):
            version = checker.get_version()
            assert version == "Cppcheck 2.13"

    def test_ensure_binary(self) -> None:
        """Test ensure_binary delegates to find_cppcheck."""
        checker = CppcheckChecker()
        with patch(
            "lucidshark.plugins.type_checkers.cppcheck.find_cppcheck",
            return_value=FAKE_BINARY,
        ):
            binary = checker.ensure_binary()
            assert binary == FAKE_BINARY

    def test_ensure_binary_raises_when_not_found(self) -> None:
        """Test ensure_binary raises FileNotFoundError."""
        checker = CppcheckChecker()
        with patch(
            "lucidshark.plugins.type_checkers.cppcheck.find_cppcheck",
            side_effect=FileNotFoundError("not found"),
        ):
            with pytest.raises(FileNotFoundError):
                checker.ensure_binary()


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestCppcheckSeverityMapping:
    """Tests for cppcheck severity mapping."""

    def test_error_maps_to_high(self) -> None:
        """Test error maps to HIGH."""
        assert CPPCHECK_SEVERITY["error"] == Severity.HIGH

    def test_warning_maps_to_medium(self) -> None:
        """Test warning maps to MEDIUM."""
        assert CPPCHECK_SEVERITY["warning"] == Severity.MEDIUM

    def test_style_maps_to_low(self) -> None:
        """Test style maps to LOW."""
        assert CPPCHECK_SEVERITY["style"] == Severity.LOW

    def test_performance_maps_to_medium(self) -> None:
        """Test performance maps to MEDIUM."""
        assert CPPCHECK_SEVERITY["performance"] == Severity.MEDIUM

    def test_portability_maps_to_medium(self) -> None:
        """Test portability maps to MEDIUM."""
        assert CPPCHECK_SEVERITY["portability"] == Severity.MEDIUM

    def test_information_maps_to_info(self) -> None:
        """Test information maps to INFO."""
        assert CPPCHECK_SEVERITY["information"] == Severity.INFO


# ---------------------------------------------------------------------------
# _DIAG_RE
# ---------------------------------------------------------------------------


class TestCppcheckDiagRegex:
    """Tests for the _DIAG_RE regex pattern."""

    def test_matches_error(self) -> None:
        """Test matching an error diagnostic."""
        line = "file.c:42:5: error: Memory leak: ptr [memleak]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(1) == "file.c"
        assert match.group(2) == "42"
        assert match.group(3) == "5"
        assert match.group(4) == "error"
        assert match.group(5) == "Memory leak: ptr"
        assert match.group(6) == "memleak"

    def test_matches_warning(self) -> None:
        """Test matching a warning diagnostic."""
        line = "src/main.c:10:1: warning: Uninitialized variable: x [uninitvar]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(4) == "warning"
        assert match.group(6) == "uninitvar"

    def test_matches_style(self) -> None:
        """Test matching a style diagnostic."""
        line = "file.c:5:3: style: Variable 'x' is assigned a value that is never used [unreadVariable]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(4) == "style"

    def test_matches_performance(self) -> None:
        """Test matching a performance diagnostic."""
        line = "file.c:15:8: performance: Consider using strncmp [stlcstr]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(4) == "performance"

    def test_matches_information(self) -> None:
        """Test matching an information diagnostic."""
        line = "file.c:1:1: information: Too few configs [toomanyconfigs]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(4) == "information"

    def test_no_match_on_garbage(self) -> None:
        """Test no match on non-diagnostic lines."""
        line = "Checking file.c..."
        match = _DIAG_RE.match(line)
        assert match is None


# ---------------------------------------------------------------------------
# _parse_output
# ---------------------------------------------------------------------------


class TestCppcheckParseOutput:
    """Tests for _parse_output method."""

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        checker = CppcheckChecker()
        issues = checker._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_whitespace_only(self) -> None:
        """Test parsing whitespace-only output."""
        checker = CppcheckChecker()
        issues = checker._parse_output("   \n\n  ", Path("/project"))
        assert issues == []

    def test_parse_single_error(self) -> None:
        """Test parsing a single error."""
        checker = CppcheckChecker()
        output = "file.c:42:5: error: Memory leak: ptr [memleak]"
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].source_tool == "cppcheck"
        assert issues[0].domain == ToolDomain.TYPE_CHECKING
        assert issues[0].severity == Severity.HIGH
        assert issues[0].rule_id == "memleak"
        assert issues[0].line_start == 42
        assert issues[0].column_start == 5
        assert issues[0].fixable is False

    def test_parse_multiple_diagnostics(self) -> None:
        """Test parsing multiple diagnostics."""
        checker = CppcheckChecker()
        output = (
            "a.c:1:1: error: Null pointer dereference [nullPointer]\n"
            "b.c:10:3: warning: Uninitialized variable [uninitvar]\n"
            "c.c:20:5: style: Unused variable [unusedVariable]\n"
        )
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 3

    def test_skips_information_level(self) -> None:
        """Test that information-level diagnostics are skipped."""
        checker = CppcheckChecker()
        output = (
            "file.c:1:1: error: real error [err]\n"
            "file.c:5:3: information: Too many configs [toomanyconfigs]\n"
        )
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].rule_id == "err"

    def test_deduplicates_issues(self) -> None:
        """Test that duplicate issues are deduplicated by ID."""
        checker = CppcheckChecker()
        output = (
            "file.c:42:5: error: Memory leak [memleak]\n"
            "file.c:42:5: error: Memory leak [memleak]\n"
        )
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1

    def test_relative_path_resolved(self) -> None:
        """Test that relative file paths are resolved against project root."""
        checker = CppcheckChecker()
        output = "src/main.c:1:1: error: msg [err]"
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].file_path == Path("/project/src/main.c").resolve()

    def test_non_diagnostic_lines_ignored(self) -> None:
        """Test that non-diagnostic lines are ignored."""
        checker = CppcheckChecker()
        output = (
            "Checking file.c...\n"
            "1/3 files checked.\n"
            "file.c:1:1: error: msg [err]\n"
            "Checking done.\n"
        )
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1

    def test_issue_metadata_contains_cppcheck_severity_and_check_id(self) -> None:
        """Test that issue metadata contains cppcheck_severity and check_id."""
        checker = CppcheckChecker()
        output = "file.c:1:1: warning: msg [uninitvar]"
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].metadata["cppcheck_severity"] == "warning"
        assert issues[0].metadata["check_id"] == "uninitvar"

    def test_issue_title_includes_check_id(self) -> None:
        """Test that issue title includes check ID in brackets."""
        checker = CppcheckChecker()
        output = "file.c:1:1: error: Memory leak [memleak]"
        issues = checker._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert "[memleak]" in issues[0].title


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


class TestCppcheckCheck:
    """Tests for check method."""

    def test_check_binary_not_found(self) -> None:
        """Test check returns empty when binary not found."""
        checker = CppcheckChecker()

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
        """Test successful type checking."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            stderr_output = "src/main.c:10:5: error: Null pointer dereference [nullPointer]"
            mock_result = make_completed_process(0, "", stderr_output)

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = checker.check(context)
                    assert len(issues) == 1
                    assert issues[0].source_tool == "cppcheck"
                    assert issues[0].domain == ToolDomain.TYPE_CHECKING
                    assert issues[0].severity == Severity.HIGH
                    assert issues[0].rule_id == "nullPointer"

    def test_check_timeout(self) -> None:
        """Test check handles timeout."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired("cppcheck", 300),
                ):
                    issues = checker.check(context)
                    assert issues == []

    def test_check_subprocess_error(self) -> None:
        """Test check handles subprocess errors."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    side_effect=OSError("command failed"),
                ):
                    issues = checker.check(context)
                    assert issues == []

    def test_check_uses_strict_mode_when_configured(self) -> None:
        """Test that --inconclusive is added when strict mode is configured."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = MagicMock(spec=ScanContext)
            context.project_root = tmpdir_path
            context.paths = [tmpdir_path]
            context.ignore_patterns = None
            context.stream_handler = None
            # Mock the config structure for strict mode
            mock_tool = MagicMock()
            mock_tool.name = "cppcheck"
            mock_tool.strict = True
            mock_type_checking = MagicMock()
            mock_type_checking.tools = [mock_tool]
            context.config.pipeline.type_checking = mock_type_checking

            mock_result = make_completed_process(0, "", "")

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    return_value=mock_result,
                ) as mock_run:
                    checker.check(context)
                    cmd = mock_run.call_args.kwargs.get("cmd") or mock_run.call_args[1].get("cmd")
                    assert "--inconclusive" in cmd

    def test_check_no_strict_mode_by_default(self) -> None:
        """Test that --inconclusive is not added by default."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = MagicMock(spec=ScanContext)
            context.project_root = tmpdir_path
            context.paths = [tmpdir_path]
            context.ignore_patterns = None
            context.stream_handler = None
            # No config → no strict mode
            context.config = None

            mock_result = make_completed_process(0, "", "")

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    return_value=mock_result,
                ) as mock_run:
                    checker.check(context)
                    cmd = mock_run.call_args.kwargs.get("cmd") or mock_run.call_args[1].get("cmd")
                    assert "--inconclusive" not in cmd

    def test_check_adds_paths_from_context(self) -> None:
        """Test that paths from context are added to cppcheck command."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()

            context = MagicMock(spec=ScanContext)
            context.project_root = tmpdir_path
            context.paths = [src_dir]
            context.ignore_patterns = None
            context.stream_handler = None
            context.config = None

            mock_result = make_completed_process(0, "", "")

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    return_value=mock_result,
                ) as mock_run:
                    checker.check(context)
                    cmd = mock_run.call_args.kwargs.get("cmd") or mock_run.call_args[1].get("cmd")
                    assert str(src_dir) in cmd

    def test_check_uses_project_root_when_no_paths(self) -> None:
        """Test that project root is used when no paths specified."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = MagicMock(spec=ScanContext)
            context.project_root = tmpdir_path
            context.paths = []
            context.ignore_patterns = None
            context.stream_handler = None
            context.config = None

            mock_result = make_completed_process(0, "", "")

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    return_value=mock_result,
                ) as mock_run:
                    checker.check(context)
                    cmd = mock_run.call_args.kwargs.get("cmd") or mock_run.call_args[1].get("cmd")
                    assert str(tmpdir_path) in cmd

    def test_check_command_includes_enable_all(self) -> None:
        """Test that --enable=all is included in command."""
        checker = CppcheckChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = MagicMock(spec=ScanContext)
            context.project_root = tmpdir_path
            context.paths = [tmpdir_path]
            context.ignore_patterns = None
            context.stream_handler = None
            context.config = None

            mock_result = make_completed_process(0, "", "")

            with patch.object(
                checker, "ensure_binary", return_value=FAKE_BINARY
            ):
                with patch(
                    "lucidshark.plugins.type_checkers.cppcheck.run_with_streaming",
                    return_value=mock_result,
                ) as mock_run:
                    checker.check(context)
                    cmd = mock_run.call_args.kwargs.get("cmd") or mock_run.call_args[1].get("cmd")
                    assert "--enable=all" in cmd
                    assert "--language=c" in cmd
                    assert "--quiet" in cmd
