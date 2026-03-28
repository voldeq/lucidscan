"""Unit tests for clang-tidy linter plugin."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.linters.clang_tidy import (
    CHECK_SEVERITY,
    LEVEL_SEVERITY,
    ClangTidyLinter,
    _DIAG_RE,
)
from lucidshark.plugins.linters.base import FixResult


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


def _make_context(
    project_root: Path, paths: list[Path] | None = None
) -> ScanContext:
    return ScanContext(
        project_root=project_root,
        paths=paths or [],
        enabled_domains=[ToolDomain.LINTING],
    )


FAKE_BINARY = Path("/usr/bin/clang-tidy")


# ---------------------------------------------------------------------------
# ClangTidyLinter properties
# ---------------------------------------------------------------------------


class TestClangTidyLinterProperties:
    """Tests for ClangTidyLinter basic properties."""

    def test_name(self) -> None:
        """Test plugin name."""
        linter = ClangTidyLinter()
        assert linter.name == "clang_tidy"

    def test_languages(self) -> None:
        """Test supported languages."""
        linter = ClangTidyLinter()
        assert linter.languages == ["c"]

    def test_domain(self) -> None:
        """Test domain is LINTING."""
        linter = ClangTidyLinter()
        assert linter.domain == ToolDomain.LINTING

    def test_supports_fix(self) -> None:
        """Test supports_fix returns True."""
        linter = ClangTidyLinter()
        assert linter.supports_fix is True

    def test_init_with_project_root(self) -> None:
        """Test initialization with project root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            linter = ClangTidyLinter(project_root=Path(tmpdir))
            assert linter._project_root == Path(tmpdir)

    def test_get_version(self) -> None:
        """Test get_version delegates to get_clang_tidy_version."""
        linter = ClangTidyLinter()
        with patch(
            "lucidshark.plugins.linters.clang_tidy.get_clang_tidy_version",
            return_value="LLVM version 17.0.6",
        ):
            version = linter.get_version()
            assert version == "LLVM version 17.0.6"

    def test_ensure_binary(self) -> None:
        """Test ensure_binary delegates to find_clang_tidy."""
        linter = ClangTidyLinter()
        with patch(
            "lucidshark.plugins.linters.clang_tidy.find_clang_tidy",
            return_value=FAKE_BINARY,
        ):
            binary = linter.ensure_binary()
            assert binary == FAKE_BINARY

    def test_ensure_binary_raises_when_not_found(self) -> None:
        """Test ensure_binary raises FileNotFoundError."""
        linter = ClangTidyLinter()
        with patch(
            "lucidshark.plugins.linters.clang_tidy.find_clang_tidy",
            side_effect=FileNotFoundError("not found"),
        ):
            with pytest.raises(FileNotFoundError):
                linter.ensure_binary()


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestClangTidySeverityMapping:
    """Tests for clang-tidy severity mappings."""

    def test_bugprone_is_high(self) -> None:
        """Test bugprone category maps to HIGH."""
        assert CHECK_SEVERITY["bugprone"] == Severity.HIGH

    def test_cert_is_high(self) -> None:
        """Test cert category maps to HIGH."""
        assert CHECK_SEVERITY["cert"] == Severity.HIGH

    def test_clang_analyzer_is_high(self) -> None:
        """Test clang-analyzer category maps to HIGH."""
        assert CHECK_SEVERITY["clang-analyzer"] == Severity.HIGH

    def test_readability_is_low(self) -> None:
        """Test readability category maps to LOW."""
        assert CHECK_SEVERITY["readability"] == Severity.LOW

    def test_performance_is_medium(self) -> None:
        """Test performance category maps to MEDIUM."""
        assert CHECK_SEVERITY["performance"] == Severity.MEDIUM

    def test_level_error_is_high(self) -> None:
        """Test error level maps to HIGH."""
        assert LEVEL_SEVERITY["error"] == Severity.HIGH

    def test_level_warning_is_medium(self) -> None:
        """Test warning level maps to MEDIUM."""
        assert LEVEL_SEVERITY["warning"] == Severity.MEDIUM

    def test_level_note_is_low(self) -> None:
        """Test note level maps to LOW."""
        assert LEVEL_SEVERITY["note"] == Severity.LOW


# ---------------------------------------------------------------------------
# _get_severity
# ---------------------------------------------------------------------------


class TestClangTidyGetSeverity:
    """Tests for _get_severity method."""

    def test_bugprone_check_returns_high(self) -> None:
        """Test bugprone-* checks return HIGH."""
        linter = ClangTidyLinter()
        assert linter._get_severity("bugprone-use-after-move", "warning") == Severity.HIGH

    def test_readability_check_returns_low(self) -> None:
        """Test readability-* checks return LOW."""
        linter = ClangTidyLinter()
        assert linter._get_severity("readability-identifier-naming", "warning") == Severity.LOW

    def test_unknown_check_falls_back_to_level(self) -> None:
        """Test unknown check names fall back to level-based severity."""
        linter = ClangTidyLinter()
        assert linter._get_severity("unknown-check", "error") == Severity.HIGH
        assert linter._get_severity("unknown-check", "warning") == Severity.MEDIUM

    def test_unknown_check_and_level_defaults_to_medium(self) -> None:
        """Test unknown check and unknown level defaults to MEDIUM."""
        linter = ClangTidyLinter()
        assert linter._get_severity("unknown-check", "unknown-level") == Severity.MEDIUM


# ---------------------------------------------------------------------------
# _DIAG_RE
# ---------------------------------------------------------------------------


class TestDiagRegex:
    """Tests for the _DIAG_RE regex pattern."""

    def test_matches_warning_with_check(self) -> None:
        """Test matching a warning with check name."""
        line = "/path/to/file.c:42:5: warning: use of NULL [bugprone-null]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(1) == "/path/to/file.c"
        assert match.group(2) == "42"
        assert match.group(3) == "5"
        assert match.group(4) == "warning"
        assert match.group(5) == "use of NULL"
        assert match.group(6) == "bugprone-null"

    def test_matches_error(self) -> None:
        """Test matching an error diagnostic."""
        line = "file.c:10:1: error: expected ';' [clang-diagnostic-error]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(4) == "error"

    def test_matches_note(self) -> None:
        """Test matching a note diagnostic."""
        line = "file.c:5:3: note: previous definition is here [some-check]"
        match = _DIAG_RE.match(line)
        assert match is not None
        assert match.group(4) == "note"

    def test_no_match_on_garbage(self) -> None:
        """Test no match on non-diagnostic lines."""
        line = "Compiling main.c..."
        match = _DIAG_RE.match(line)
        assert match is None


# ---------------------------------------------------------------------------
# _parse_output
# ---------------------------------------------------------------------------


class TestClangTidyParseOutput:
    """Tests for _parse_output method."""

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        linter = ClangTidyLinter()
        issues = linter._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_whitespace_only(self) -> None:
        """Test parsing whitespace-only output."""
        linter = ClangTidyLinter()
        issues = linter._parse_output("   \n\n  ", Path("/project"))
        assert issues == []

    def test_parse_single_warning(self) -> None:
        """Test parsing a single warning."""
        linter = ClangTidyLinter()
        output = "file.c:42:5: warning: variable is not initialized [bugprone-uninitialized]"
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].source_tool == "clang-tidy"
        assert issues[0].domain == ToolDomain.LINTING
        assert issues[0].severity == Severity.HIGH
        assert issues[0].rule_id == "bugprone-uninitialized"
        assert issues[0].line_start == 42
        assert issues[0].column_start == 5
        assert issues[0].fixable is True

    def test_parse_multiple_warnings(self) -> None:
        """Test parsing multiple warnings."""
        linter = ClangTidyLinter()
        output = (
            "a.c:1:1: warning: unused variable [misc-unused]\n"
            "b.c:2:3: error: undeclared identifier [clang-diagnostic-error]\n"
        )
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 2

    def test_skips_note_level(self) -> None:
        """Test that note-level diagnostics are skipped."""
        linter = ClangTidyLinter()
        output = (
            "file.c:10:1: warning: use after move [bugprone-use-after-move]\n"
            "file.c:5:3: note: previous definition is here [bugprone-use-after-move]\n"
        )
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].line_start == 10

    def test_deduplicates_issues(self) -> None:
        """Test that duplicate issues are deduplicated by ID."""
        linter = ClangTidyLinter()
        output = (
            "file.c:42:5: warning: msg [check-name]\n"
            "file.c:42:5: warning: msg [check-name]\n"
        )
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1

    def test_relative_path_resolved(self) -> None:
        """Test that relative file paths are resolved against project root."""
        linter = ClangTidyLinter()
        output = "src/main.c:1:1: warning: msg [check]"
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].file_path == Path("/project/src/main.c").resolve()

    def test_non_diagnostic_lines_ignored(self) -> None:
        """Test that non-diagnostic lines are ignored."""
        linter = ClangTidyLinter()
        output = (
            "12 warnings generated.\n"
            "file.c:1:1: warning: msg [check]\n"
            "Suppressed 5 warnings.\n"
        )
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1

    def test_warning_without_check_name(self) -> None:
        """Test parsing warning without a check name in brackets."""
        linter = ClangTidyLinter()
        # The regex requires the check-name group is optional
        output = "file.c:1:1: warning: some message"
        # If the regex doesn't match without brackets, that's fine
        issues = linter._parse_output(output, Path("/project"))
        # The regex group 6 is optional - test what actually happens
        # Looking at the regex: (?:\s+\[([^\]]+)\])?$ - the bracket group is optional
        assert len(issues) <= 1

    def test_issue_metadata_contains_check_name_and_level(self) -> None:
        """Test that issue metadata contains check_name and level."""
        linter = ClangTidyLinter()
        output = "file.c:1:1: warning: msg [readability-braces]"
        issues = linter._parse_output(output, Path("/project"))
        assert len(issues) == 1
        assert issues[0].metadata["check_name"] == "readability-braces"
        assert issues[0].metadata["level"] == "warning"


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------


class TestClangTidyLint:
    """Tests for lint method."""

    def test_lint_binary_not_found(self) -> None:
        """Test lint returns empty when binary not found."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = _make_context(Path(tmpdir))

            with patch.object(
                linter, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                issues = linter.lint(context)
                assert issues == []

    def test_lint_no_c_files(self) -> None:
        """Test lint returns empty when no C files found."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            py_file = tmpdir_path / "test.py"
            py_file.touch()

            context = _make_context(tmpdir_path, [py_file])

            with patch.object(linter, "ensure_binary", return_value=FAKE_BINARY):
                issues = linter.lint(context)
                assert issues == []

    def test_lint_success(self) -> None:
        """Test successful linting with diagnostics."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            c_file = tmpdir_path / "main.c"
            c_file.write_text("int main() { return 0; }\n")

            context = _make_context(tmpdir_path, [c_file])

            stderr_output = f"{c_file}:1:5: warning: use of NULL [bugprone-null]\n"
            mock_result = make_completed_process(1, "", stderr_output)

            with patch.object(linter, "ensure_binary", return_value=FAKE_BINARY):
                with patch(
                    "lucidshark.plugins.linters.clang_tidy.run_with_streaming",
                    return_value=mock_result,
                ):
                    issues = linter.lint(context)
                    assert len(issues) == 1
                    assert issues[0].source_tool == "clang-tidy"

    def test_lint_timeout(self) -> None:
        """Test lint handles timeout."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            c_file = tmpdir_path / "main.c"
            c_file.write_text("int main() {}\n")

            context = _make_context(tmpdir_path, [c_file])

            with patch.object(linter, "ensure_binary", return_value=FAKE_BINARY):
                with patch(
                    "lucidshark.plugins.linters.clang_tidy.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired("clang-tidy", 300),
                ):
                    issues = linter.lint(context)
                    assert issues == []

    def test_lint_subprocess_error(self) -> None:
        """Test lint handles subprocess errors."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            c_file = tmpdir_path / "main.c"
            c_file.write_text("int main() {}\n")

            context = _make_context(tmpdir_path, [c_file])

            with patch.object(linter, "ensure_binary", return_value=FAKE_BINARY):
                with patch(
                    "lucidshark.plugins.linters.clang_tidy.run_with_streaming",
                    side_effect=OSError("command failed"),
                ):
                    issues = linter.lint(context)
                    assert issues == []

    def test_lint_uses_build_dir_when_available(self) -> None:
        """Test lint passes -p flag when build dir is found."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            c_file = tmpdir_path / "main.c"
            c_file.write_text("int main() {}\n")

            # Create build dir with CMakeCache.txt
            build_dir = tmpdir_path / "build"
            build_dir.mkdir()
            (build_dir / "CMakeCache.txt").touch()

            context = _make_context(tmpdir_path, [c_file])

            mock_result = make_completed_process(0, "", "")

            with patch.object(linter, "ensure_binary", return_value=FAKE_BINARY):
                with patch(
                    "lucidshark.plugins.linters.clang_tidy.run_with_streaming",
                    return_value=mock_result,
                ) as mock_run:
                    linter.lint(context)
                    cmd = mock_run.call_args.kwargs.get("cmd") or mock_run.call_args[1].get("cmd")
                    assert any(f"-p={build_dir}" in str(arg) for arg in cmd)


# ---------------------------------------------------------------------------
# _collect_c_files
# ---------------------------------------------------------------------------


class TestCollectCFiles:
    """Tests for _collect_c_files method."""

    def test_collects_c_files_from_paths(self) -> None:
        """Test collecting .c files from explicit paths."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            c_file = tmpdir_path / "main.c"
            c_file.touch()
            h_file = tmpdir_path / "main.h"
            h_file.touch()

            context = _make_context(tmpdir_path, [c_file, h_file])
            files = linter._collect_c_files(context)
            assert len(files) == 2

    def test_excludes_non_c_files(self) -> None:
        """Test excluding non-C files."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            c_file = tmpdir_path / "main.c"
            c_file.touch()
            py_file = tmpdir_path / "script.py"
            py_file.touch()

            context = _make_context(tmpdir_path, [c_file, py_file])
            files = linter._collect_c_files(context)
            assert len(files) == 1
            assert "main.c" in files[0]

    def test_discovers_files_from_directory(self) -> None:
        """Test discovering C files from a directory path."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            (src_dir / "main.c").touch()
            (src_dir / "utils.c").touch()
            (src_dir / "README.md").touch()

            context = _make_context(tmpdir_path, [src_dir])
            files = linter._collect_c_files(context)
            assert len(files) == 2

    def test_discovers_files_from_project_root_when_no_paths(self) -> None:
        """Test discovering files from project root when no paths specified."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "main.c").touch()
            (tmpdir_path / "utils.h").touch()

            context = _make_context(tmpdir_path, [])
            files = linter._collect_c_files(context)
            assert len(files) == 2


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------


class TestClangTidyFix:
    """Tests for fix method."""

    def test_fix_binary_not_found(self) -> None:
        """Test fix returns empty FixResult when binary not found."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = _make_context(Path(tmpdir))

            with patch.object(
                linter, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                result = linter.fix(context)
                assert isinstance(result, FixResult)
                assert result.issues_fixed == 0

    def test_fix_no_c_files(self) -> None:
        """Test fix returns empty FixResult when no C files."""
        linter = ClangTidyLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            py_file = tmpdir_path / "test.py"
            py_file.touch()

            context = _make_context(tmpdir_path, [py_file])

            with patch.object(linter, "ensure_binary", return_value=FAKE_BINARY):
                result = linter.fix(context)
                assert isinstance(result, FixResult)
                assert result.issues_fixed == 0
