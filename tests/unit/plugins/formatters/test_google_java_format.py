"""Unit tests for Google Java Format formatter plugin."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.formatters.google_java_format import (
    GoogleJavaFormatFormatter,
    JAVA_EXTENSIONS,
)
from lucidshark.plugins.linters.base import FixResult


def make_completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _make_context(project_root: Path, paths: list[Path] | None = None) -> ScanContext:
    """Helper to build a ScanContext."""
    return ScanContext(
        project_root=project_root,
        paths=paths or [],
        enabled_domains=[ToolDomain.FORMATTING],
    )


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestGoogleJavaFormatProperties:
    def test_name(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        assert formatter.name == "google_java_format"

    def test_languages(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        assert formatter.languages == ["java"]

    def test_domain(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        assert formatter.domain == ToolDomain.FORMATTING

    def test_extensions(self) -> None:
        assert ".java" in JAVA_EXTENSIONS

    def test_supports_fix(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        assert formatter.supports_fix is True


# ---------------------------------------------------------------------------
# ensure_binary
# ---------------------------------------------------------------------------


class TestGoogleJavaFormatEnsureBinary:
    def test_not_found(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        with patch(
            "lucidshark.plugins.formatters.google_java_format.shutil.which",
            return_value=None,
        ):
            with pytest.raises(FileNotFoundError):
                formatter.ensure_binary()

    def test_found(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        with patch(
            "lucidshark.plugins.formatters.google_java_format.shutil.which",
            return_value="/usr/bin/google-java-format",
        ):
            binary = formatter.ensure_binary()
            assert binary == Path("/usr/bin/google-java-format")


# ---------------------------------------------------------------------------
# get_version
# ---------------------------------------------------------------------------


class TestGoogleJavaFormatGetVersion:
    def test_get_version_success(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        with (
            patch.object(
                formatter,
                "ensure_binary",
                return_value=Path("/usr/bin/google-java-format"),
            ),
            patch(
                "lucidshark.plugins.formatters.google_java_format.get_cli_version",
                return_value="1.19.2",
            ),
        ):
            assert formatter.get_version() == "1.19.2"

    def test_get_version_binary_not_found(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            assert formatter.get_version() == "unknown"


# ---------------------------------------------------------------------------
# _resolve_paths
# ---------------------------------------------------------------------------


class TestGoogleJavaFormatResolvePaths:
    def test_directories_expanded_to_java_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            subdir = project_root / "src"
            subdir.mkdir()
            java_file = subdir / "Main.java"
            java_file.touch()

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [subdir])
            result = formatter._resolve_paths(
                context, JAVA_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(java_file)]

    def test_skips_non_java_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])
            result = formatter._resolve_paths(
                context, JAVA_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == []

    def test_mixed_java_and_non_java(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Main.java"
            java_file.write_text("class Main {}\n")
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")
            txt_file = project_root / "notes.txt"
            txt_file.write_text("notes\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file, py_file, txt_file])
            result = formatter._resolve_paths(
                context, JAVA_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(java_file)]

    def test_accepts_java_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "App.java"
            java_file.write_text("class App {}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])
            result = formatter._resolve_paths(
                context, JAVA_EXTENSIONS, fallback_to_cwd=False
            )
            assert result == [str(java_file)]


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


class TestGoogleJavaFormatCheck:
    def test_check_no_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Main.java"
            java_file.write_text("class Main {}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            result = make_completed_process(0, "")
            with (
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_with_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Main.java"
            java_file.write_text("class Main{}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            # --dry-run outputs reformatted source, not file paths; exit code 1 = needs formatting
            result = make_completed_process(1, "class Main {}\n")
            with (
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert issues[0].domain == ToolDomain.FORMATTING
                assert issues[0].source_tool == "google_java_format"
                assert issues[0].severity == Severity.LOW
                assert issues[0].fixable is True

    def test_check_multiple_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            file_a = project_root / "A.java"
            file_b = project_root / "B.java"
            file_a.write_text("class A{}\n")
            file_b.write_text("class B{}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [file_a, file_b])

            # Per-file check: each file returns exit code 1 (needs formatting)
            result = make_completed_process(1, "class A {}\n")
            with (
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
            ):
                issues = formatter.check(context)
                assert len(issues) == 2

    def test_check_mixed_formatted_and_unformatted(self) -> None:
        """Only files with non-zero exit code are reported."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            file_ok = project_root / "Ok.java"
            file_bad = project_root / "Bad.java"
            file_ok.write_text("class Ok {}\n")
            file_bad.write_text("class Bad{}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [file_ok, file_bad])

            results = [
                make_completed_process(0, "class Ok {}\n"),  # Ok.java is fine
                make_completed_process(
                    1, "class Bad {}\n"
                ),  # Bad.java needs formatting
            ]
            with (
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    side_effect=results,
                ),
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert str(file_bad) in issues[0].title

    def test_check_skips_non_java_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])

            issues = formatter.check(context)
            assert issues == []

    def test_check_binary_not_found(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        context = _make_context(Path("/tmp"), [])
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            issues = formatter.check(context)
            assert issues == []

    def test_check_context_paths_falsy_returns_empty(self) -> None:
        """When context.paths is an empty list, check returns [] without invoking subprocess."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, paths=[])

            with (
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                ) as mock_run,
            ):
                issues = formatter.check(context)
                assert issues == []
                mock_run.assert_not_called()

    def test_check_timeout_expired(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Slow.java"
            java_file.write_text("class Slow {}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            with (
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    side_effect=subprocess.TimeoutExpired(
                        cmd="google-java-format", timeout=120
                    ),
                ),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_generic_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Bad.java"
            java_file.write_text("class Bad {}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            with (
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    side_effect=RuntimeError("unexpected crash"),
                ),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_nonzero_exit_reports_file(self) -> None:
        """Non-zero exit means the file needs formatting, regardless of stdout content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Empty.java"
            java_file.write_text("class Empty {}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            result = make_completed_process(1, "")
            with (
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    return_value=result,
                ),
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
            ):
                issues = formatter.check(context)
                assert len(issues) == 1


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------


class TestGoogleJavaFormatFix:
    def test_fix_success(self) -> None:
        """fix() runs --replace without pre-check (runner does post-check)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Main.java"
            java_file.write_text("class Main{}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            fix_run_result = make_completed_process(0, "")

            with (
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    return_value=fix_run_result,
                ),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 1
                assert result.issues_remaining == 0

    def test_fix_binary_not_found(self) -> None:
        formatter = GoogleJavaFormatFormatter()
        context = _make_context(Path("/tmp"), [])

        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            result = formatter.fix(context)
            assert isinstance(result, FixResult)
            assert result.files_modified == 0
            assert result.issues_fixed == 0

    def test_fix_no_matching_paths(self) -> None:
        """fix() returns empty FixResult when there are no java files to format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            py_file = project_root / "main.py"
            py_file.write_text("x = 1\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [py_file])

            with patch.object(
                formatter,
                "ensure_binary",
                return_value=Path("/usr/bin/google-java-format"),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 0
                assert result.issues_fixed == 0

    def test_fix_subprocess_exception(self) -> None:
        """fix() returns empty FixResult when the --replace subprocess raises."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            java_file = project_root / "Crash.java"
            java_file.write_text("class Crash{}\n")

            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, [java_file])

            with (
                patch.object(
                    formatter,
                    "ensure_binary",
                    return_value=Path("/usr/bin/google-java-format"),
                ),
                patch(
                    "lucidshark.plugins.formatters.google_java_format.run_with_streaming",
                    side_effect=RuntimeError("disk full"),
                ),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 0
                assert result.issues_fixed == 0

    def test_fix_empty_paths_list(self) -> None:
        """fix() returns empty FixResult when context.paths is empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            formatter = GoogleJavaFormatFormatter(project_root=project_root)
            context = _make_context(project_root, paths=[])

            with patch.object(
                formatter,
                "ensure_binary",
                return_value=Path("/usr/bin/google-java-format"),
            ):
                result = formatter.fix(context)
                assert isinstance(result, FixResult)
                assert result.files_modified == 0
                assert result.issues_fixed == 0
