"""Unit tests for Rustfmt formatter plugin."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.formatters.rustfmt import RustfmtFormatter, RUST_EXTENSIONS
from lucidshark.plugins.linters.base import FixResult


def make_completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _make_context(project_root: Path, paths: list[Path] | None = None) -> ScanContext:
    return ScanContext(
        project_root=project_root,
        paths=paths or [],
        enabled_domains=[ToolDomain.FORMATTING],
    )


FAKE_BINARY = Path("/usr/bin/rustfmt")


class TestRustfmtFormatterProperties:
    def test_name(self) -> None:
        formatter = RustfmtFormatter()
        assert formatter.name == "rustfmt"

    def test_languages(self) -> None:
        formatter = RustfmtFormatter()
        assert formatter.languages == ["rust"]

    def test_domain(self) -> None:
        formatter = RustfmtFormatter()
        assert formatter.domain == ToolDomain.FORMATTING

    def test_extensions(self) -> None:
        assert ".rs" in RUST_EXTENSIONS

    def test_supports_fix(self) -> None:
        formatter = RustfmtFormatter()
        assert formatter.supports_fix is True


class TestRustfmtFormatterGetVersion:
    def test_get_version_success(self) -> None:
        formatter = RustfmtFormatter()
        with (
            patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            patch(
                "lucidshark.plugins.formatters.rustfmt.get_cli_version",
                return_value="1.6.0",
            ),
        ):
            version = formatter.get_version()
            assert version == "1.6.0"

    def test_get_version_binary_not_found(self) -> None:
        formatter = RustfmtFormatter()
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            version = formatter.get_version()
            assert version == "unknown"


class TestRustfmtFormatterEnsureBinary:
    def test_not_found(self) -> None:
        formatter = RustfmtFormatter()
        with patch(
            "lucidshark.plugins.formatters.rustfmt.shutil.which", return_value=None
        ):
            with pytest.raises(FileNotFoundError):
                formatter.ensure_binary()

    def test_found(self) -> None:
        formatter = RustfmtFormatter()
        with patch(
            "lucidshark.plugins.formatters.rustfmt.shutil.which",
            return_value="/usr/bin/rustfmt",
        ):
            binary = formatter.ensure_binary()
            assert binary == Path("/usr/bin/rustfmt")


class TestRustfmtResolvePaths:
    def test_directories_expanded_to_rs_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            subdir = project_root / "src"
            subdir.mkdir()
            rs_file = subdir / "main.rs"
            rs_file.touch()

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [subdir])
            result = formatter._resolve_paths(
                context, RUST_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(rs_file)]

    def test_skips_non_rust_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])
            result = formatter._resolve_paths(
                context, RUST_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == []

    def test_includes_rs_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main() {}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])
            result = formatter._resolve_paths(
                context, RUST_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(rs_file)]

    def test_mixed_valid_and_invalid_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "lib.rs"
            rs_file.write_text("")
            py_file = project_root / "script.py"
            py_file.write_text("")
            txt_file = project_root / "notes.txt"
            txt_file.write_text("")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file, py_file, txt_file])
            result = formatter._resolve_paths(
                context, RUST_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(rs_file)]


class TestRustfmtFormatterCheck:
    def test_check_no_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main() {}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            result = make_completed_process(0, "")
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_with_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main(){}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            stdout = "Diff in main.rs at line 1:\n-fn main(){}\n+fn main() {}\n"
            result = make_completed_process(1, stdout)
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert issues[0].domain == ToolDomain.FORMATTING
                assert issues[0].source_tool == "rustfmt"
                assert issues[0].severity == Severity.LOW
                assert issues[0].fixable is True

    def test_check_skips_non_rust_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])

            issues = formatter.check(context)
            assert issues == []

    def test_check_binary_not_found(self) -> None:
        formatter = RustfmtFormatter()
        context = _make_context(Path("/tmp"))
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            issues = formatter.check(context)
            assert issues == []

    def test_check_timeout_expired(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main() {}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired(cmd="rustfmt", timeout=120),
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_generic_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main() {}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    side_effect=RuntimeError("unexpected error"),
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_empty_paths_returns_empty(self) -> None:
        """When context.paths is falsy (empty list), check returns empty."""
        formatter = RustfmtFormatter()
        context = _make_context(Path("/tmp"), paths=[])

        with patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY):
            issues = formatter.check(context)
            assert issues == []

    def test_check_empty_stdout_on_nonzero_returncode(self) -> None:
        """Non-zero return code but empty stdout and stderr produces no issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main() {}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            result = make_completed_process(1, "", "")
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_parses_diff_from_stderr(self) -> None:
        """Issues found via 'Diff in' lines in stderr are also captured."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "lib.rs"
            rs_file.write_text("")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            stderr = "Diff in lib.rs at line 5:\n-old\n+new\n"
            result = make_completed_process(1, "", stderr)
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert "lib.rs" in issues[0].title

    def test_check_deduplicates_same_file_multiple_diffs(self) -> None:
        """Multiple 'Diff in' lines for the same file produce only one issue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            stdout = (
                "Diff in main.rs at line 1:\n"
                "-a\n+b\n"
                "Diff in main.rs at line 10:\n"
                "-c\n+d\n"
            )
            result = make_completed_process(1, stdout)
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1

    def test_check_multiple_different_files(self) -> None:
        """Multiple different files each produce their own issue, sorted by path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file_a = project_root / "a.rs"
            rs_file_a.write_text("")
            rs_file_b = project_root / "b.rs"
            rs_file_b.write_text("")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file_a, rs_file_b])

            stdout = (
                "Diff in b.rs at line 1:\n-x\n+y\nDiff in a.rs at line 1:\n-m\n+n\n"
            )
            result = make_completed_process(1, stdout)
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 2
                # Issues should be sorted by file path
                assert "a.rs" in issues[0].title
                assert "b.rs" in issues[1].title

    def test_check_deduplicates_across_stdout_and_stderr(self) -> None:
        """Same file in both stdout and stderr only produces one issue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            stdout = "Diff in main.rs at line 1:\n-a\n+b\n"
            stderr = "Diff in main.rs at line 5:\n-c\n+d\n"
            result = make_completed_process(1, stdout, stderr)
            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1


class TestRustfmtFormatterFix:
    def test_fix_success(self) -> None:
        """Fix resolves all pre-existing issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main(){}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            # fix runs rustfmt (no pre-check; runner does post-check)
            fix_run_result = make_completed_process(0, "")

            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    return_value=fix_run_result,
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 1
                assert result.issues_remaining == 0

    def test_fix_binary_not_found(self) -> None:
        formatter = RustfmtFormatter()
        context = _make_context(Path("/tmp"))
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            result = formatter.fix(context)
            assert isinstance(result, FixResult)
            assert result.files_modified == 0
            assert result.issues_fixed == 0

    def test_fix_no_matching_paths(self) -> None:
        """Fix with no .rs files returns empty FixResult."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = RustfmtFormatter(project_root=project_root)
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
            rs_file = project_root / "main.rs"
            rs_file.write_text("fn main(){}\n")

            formatter = RustfmtFormatter(project_root=project_root)
            context = _make_context(project_root, [rs_file])

            with (
                patch(
                    "lucidshark.plugins.formatters.rustfmt.run_with_streaming",
                    side_effect=RuntimeError("rustfmt crashed"),
                ),
                patch.object(formatter, "ensure_binary", return_value=FAKE_BINARY),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 0
                assert result.issues_fixed == 0
                assert result.issues_remaining == 0
