"""Unit tests for clang-format formatter plugin."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.formatters.clang_format import ClangFormatFormatter
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
        enabled_domains=[ToolDomain.FORMATTING],
    )


FAKE_BINARY = Path("/usr/bin/clang-format")


# ---------------------------------------------------------------------------
# ClangFormatFormatter properties
# ---------------------------------------------------------------------------


class TestClangFormatFormatterProperties:
    """Tests for ClangFormatFormatter basic properties."""

    def test_name(self) -> None:
        """Test plugin name."""
        formatter = ClangFormatFormatter()
        assert formatter.name == "clang_format"

    def test_languages(self) -> None:
        """Test supported languages."""
        formatter = ClangFormatFormatter()
        assert formatter.languages == ["c"]

    def test_domain(self) -> None:
        """Test domain is FORMATTING."""
        formatter = ClangFormatFormatter()
        assert formatter.domain == ToolDomain.FORMATTING

    def test_supports_fix(self) -> None:
        """Test supports_fix returns True (formatters always support fix)."""
        formatter = ClangFormatFormatter()
        assert formatter.supports_fix is True

    def test_get_version(self) -> None:
        """Test get_version delegates to get_clang_format_version."""
        formatter = ClangFormatFormatter()
        with patch(
            "lucidshark.plugins.formatters.clang_format.get_clang_format_version",
            return_value="clang-format version 17.0.6",
        ):
            version = formatter.get_version()
            assert version == "clang-format version 17.0.6"

    def test_ensure_binary(self) -> None:
        """Test ensure_binary delegates to find_clang_format."""
        formatter = ClangFormatFormatter()
        with patch(
            "lucidshark.plugins.formatters.clang_format.find_clang_format",
            return_value=FAKE_BINARY,
        ):
            binary = formatter.ensure_binary()
            assert binary == FAKE_BINARY

    def test_ensure_binary_raises_when_not_found(self) -> None:
        """Test ensure_binary raises FileNotFoundError."""
        formatter = ClangFormatFormatter()
        with patch(
            "lucidshark.plugins.formatters.clang_format.find_clang_format",
            side_effect=FileNotFoundError("not found"),
        ):
            with pytest.raises(FileNotFoundError):
                formatter.ensure_binary()


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


class TestClangFormatCheck:
    """Tests for check method."""

    def test_check_no_issues(self) -> None:
        """Test check returns empty when all files are formatted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main() { return 0; }\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            result = make_completed_process(0, "", "")
            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_with_issues(self) -> None:
        """Test check returns issues when files need formatting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main(){return 0;}\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            stderr = f"{c_file}:1:10: warning: code should be clang-formatted [-Wclang-format-violations]\n"
            result = make_completed_process(1, "", stderr)
            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert issues[0].domain == ToolDomain.FORMATTING
                assert issues[0].source_tool == "clang-format"
                assert issues[0].severity == Severity.LOW
                assert issues[0].fixable is True

    def test_check_binary_not_found(self) -> None:
        """Test check returns empty when binary not found."""
        formatter = ClangFormatFormatter()
        context = _make_context(Path("/tmp"))
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            issues = formatter.check(context)
            assert issues == []

    def test_check_skips_non_c_files(self) -> None:
        """Test check returns empty for non-C files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])

            with patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY):
                issues = formatter.check(context)
                assert issues == []

    def test_check_timeout_expired(self) -> None:
        """Test check handles timeout gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main() {}\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired(cmd="clang-format", timeout=120),
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_generic_exception(self) -> None:
        """Test check handles generic exceptions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main() {}\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    side_effect=RuntimeError("unexpected error"),
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_empty_paths_returns_empty(self) -> None:
        """When context.paths is empty, check returns empty."""
        formatter = ClangFormatFormatter()
        context = _make_context(Path("/tmp"), paths=[])

        with patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY):
            issues = formatter.check(context)
            assert issues == []

    def test_check_nonzero_return_but_unparseable_stderr_creates_issues(self) -> None:
        """Non-zero return code with unparseable stderr creates issues for all files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main() {}\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            # stderr doesn't contain any of the path strings
            result = make_completed_process(1, "", "some unrecognized output")
            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                # Should create issues for all checked files as fallback
                assert len(issues) == 1

    def test_check_deduplicates_files(self) -> None:
        """Multiple stderr lines for same file produce only one issue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int x;\nint y;\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            stderr = (
                f"{c_file}:1:1: warning: code should be clang-formatted\n"
                f"{c_file}:2:1: warning: code should be clang-formatted\n"
            )
            result = make_completed_process(1, "", stderr)
            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1

    def test_check_multiple_files(self) -> None:
        """Multiple files that need formatting produce separate issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file_a = project_root / "a.c"
            c_file_a.write_text("int x;\n")
            c_file_b = project_root / "b.c"
            c_file_b.write_text("int y;\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file_a, c_file_b])

            stderr = (
                f"{c_file_a}:1:1: warning: code should be clang-formatted\n"
                f"{c_file_b}:1:1: warning: code should be clang-formatted\n"
            )
            result = make_completed_process(1, "", stderr)
            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 2

    def test_check_issue_id_is_deterministic(self) -> None:
        """Issue IDs are deterministic for the same file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int x;\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            stderr = f"{c_file}:1:1: warning: code should be clang-formatted\n"
            result = make_completed_process(1, "", stderr)
            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues1 = formatter.check(context)
                issues2 = formatter.check(context)
                assert issues1[0].id == issues2[0].id


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------


class TestClangFormatFix:
    """Tests for fix method."""

    def test_fix_success(self) -> None:
        """Test successful fix operation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main(){return 0;}\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            fix_run_result = make_completed_process(0, "")

            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=fix_run_result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 1
                assert result.issues_remaining == 0

    def test_fix_binary_not_found(self) -> None:
        """Test fix returns empty FixResult when binary not found."""
        formatter = ClangFormatFormatter()
        context = _make_context(Path("/tmp"))
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            result = formatter.fix(context)
            assert isinstance(result, FixResult)
            assert result.files_modified == 0
            assert result.issues_fixed == 0

    def test_fix_no_matching_paths(self) -> None:
        """Fix with no .c files returns empty FixResult."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])

            with patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 0
                assert result.issues_fixed == 0

    def test_fix_subprocess_exception(self) -> None:
        """Fix returns empty FixResult when subprocess raises an exception."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "main.c"
            c_file.write_text("int main(){}\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file])

            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    side_effect=RuntimeError("clang-format crashed"),
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 0
                assert result.issues_fixed == 0

    def test_fix_multiple_files(self) -> None:
        """Fix with multiple C files reports correct files_modified count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file_a = project_root / "a.c"
            c_file_a.write_text("int x;\n")
            c_file_b = project_root / "b.c"
            c_file_b.write_text("int y;\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file_a, c_file_b])

            fix_run_result = make_completed_process(0, "")

            with (
                patch(
                    "lucidshark.plugins.formatters.clang_format.run_with_streaming",
                    return_value=fix_run_result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 2


# ---------------------------------------------------------------------------
# _resolve_paths
# ---------------------------------------------------------------------------


class TestClangFormatResolvePaths:
    """Tests for path resolution inherited from FormatterPlugin."""

    def test_directories_expanded_to_c_files(self) -> None:
        """Test directories are expanded to find .c files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            subdir = project_root / "src"
            subdir.mkdir()
            c_file = subdir / "main.c"
            c_file.touch()

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [subdir])
            from lucidshark.plugins.c_utils import C_EXTENSIONS

            result = formatter._resolve_paths(
                context, C_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(c_file)]

    def test_skips_non_c_files(self) -> None:
        """Test non-C files are excluded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])
            from lucidshark.plugins.c_utils import C_EXTENSIONS

            result = formatter._resolve_paths(
                context, C_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == []

    def test_includes_h_files(self) -> None:
        """Test .h header files are included."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            h_file = project_root / "header.h"
            h_file.write_text("void foo();\n")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [h_file])
            from lucidshark.plugins.c_utils import C_EXTENSIONS

            result = formatter._resolve_paths(
                context, C_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(h_file)]

    def test_mixed_valid_and_invalid_files(self) -> None:
        """Test filtering with mixed file types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            c_file = project_root / "lib.c"
            c_file.write_text("")
            py_file = project_root / "script.py"
            py_file.write_text("")
            txt_file = project_root / "notes.txt"
            txt_file.write_text("")

            formatter = ClangFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [c_file, py_file, txt_file])
            from lucidshark.plugins.c_utils import C_EXTENSIONS

            result = formatter._resolve_paths(
                context, C_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(c_file)]
