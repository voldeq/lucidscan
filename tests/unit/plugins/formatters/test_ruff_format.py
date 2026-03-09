"""Unit tests for Ruff formatter plugin."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.formatters.ruff_format import (
    RuffFormatter,
    PYTHON_EXTENSIONS,
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


class TestRuffFormatterProperties:
    """Tests for RuffFormatter basic properties."""

    def test_name(self) -> None:
        formatter = RuffFormatter()
        assert formatter.name == "ruff_format"

    def test_languages(self) -> None:
        formatter = RuffFormatter()
        assert formatter.languages == ["python"]

    def test_domain(self) -> None:
        formatter = RuffFormatter()
        assert formatter.domain == ToolDomain.FORMATTING

    def test_supports_fix(self) -> None:
        formatter = RuffFormatter()
        assert formatter.supports_fix is True

    def test_python_extensions(self) -> None:
        assert ".py" in PYTHON_EXTENSIONS
        assert ".pyi" in PYTHON_EXTENSIONS
        assert ".pyw" in PYTHON_EXTENSIONS


class TestRuffFormatterCheck:
    """Tests for RuffFormatter.check()."""

    def test_check_no_issues(self) -> None:
        """Test check returns empty list when all files are formatted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x = 1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            result = make_completed_process(0, "")
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_with_issues(self) -> None:
        """Test check returns issues for unformatted files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            stdout = "Would reformat: test.py\n"
            result = make_completed_process(1, stdout)
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert issues[0].domain == ToolDomain.FORMATTING
                assert issues[0].source_tool == "ruff_format"
                assert issues[0].severity == Severity.LOW
                assert issues[0].rule_id == "format"
                assert issues[0].fixable is True

    def test_check_skips_non_python(self) -> None:
        """Test that non-Python files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.js").write_text("const x = 1;\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.js"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            issues = formatter.check(context)
            assert issues == []

    def test_check_binary_not_found(self) -> None:
        """Test graceful handling when ruff is not installed."""
        formatter = RuffFormatter(project_root=Path("/nonexistent"))
        context = ScanContext(
            project_root=Path("/nonexistent"),
            paths=[],
            enabled_domains=[ToolDomain.FORMATTING],
        )

        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            issues = formatter.check(context)
            assert issues == []

    def test_check_multiple_files(self) -> None:
        """Test check with multiple unformatted files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "a.py").write_text("x=1\n")
            (project_root / "b.py").write_text("y=2\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "a.py", project_root / "b.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            stdout = "Would reformat: a.py\nWould reformat: b.py\n"
            result = make_completed_process(1, stdout)
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ):
                issues = formatter.check(context)
                assert len(issues) == 2

    def test_check_timeout_returns_empty(self) -> None:
        """Test that subprocess.TimeoutExpired returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                side_effect=subprocess.TimeoutExpired(cmd="ruff", timeout=120),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_generic_exception_returns_empty(self) -> None:
        """Test that a generic Exception from subprocess returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                side_effect=RuntimeError("unexpected error"),
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_falsy_paths_uses_dot(self) -> None:
        """Test that falsy context.paths falls back to ['.']."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            result = make_completed_process(0, "")
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ) as mock_run:
                issues = formatter.check(context)
                assert issues == []
                # Verify "." was passed as the path argument
                cmd_called = (
                    mock_run.call_args[1].get("cmd") or mock_run.call_args[0][0]
                )
                assert "." in cmd_called

    def test_check_empty_stdout_on_nonzero_returns_empty(self) -> None:
        """Test that empty stdout on non-zero returncode returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            result = make_completed_process(1, "")
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ):
                issues = formatter.check(context)
                assert issues == []

    def test_check_skips_error_lines(self) -> None:
        """Test that lines starting with 'error' are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            stdout = "error: Failed to parse something\nWould reformat: test.py\n"
            result = make_completed_process(1, stdout)
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert "test.py" in issues[0].title

    def test_check_bare_file_paths(self) -> None:
        """Test that bare file paths without 'Would reformat:' prefix are handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "bare.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "bare.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            stdout = "bare.py\n"
            result = make_completed_process(1, stdout)
            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=result,
            ):
                issues = formatter.check(context)
                assert len(issues) == 1
                assert "bare.py" in issues[0].title


class TestRuffFormatterFix:
    """Tests for RuffFormatter.fix()."""

    def test_fix_applies_formatting(self) -> None:
        """Test fix applies formatting and returns FixResult."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            # fix runs ruff format (no pre-check; runner does post-check)
            fix_run_result = make_completed_process(0, "1 file reformatted\n")

            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                return_value=fix_run_result,
            ):
                fix_result = formatter.fix(context)
                assert fix_result.issues_fixed == 1
                assert fix_result.issues_remaining == 0

    def test_fix_binary_not_found(self) -> None:
        """Test graceful handling when ruff is not installed."""
        formatter = RuffFormatter(project_root=Path("/nonexistent"))
        context = ScanContext(
            project_root=Path("/nonexistent"),
            paths=[],
            enabled_domains=[ToolDomain.FORMATTING],
        )

        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            fix_result = formatter.fix(context)
            assert fix_result.files_modified == 0
            assert fix_result.issues_fixed == 0

    def test_fix_no_matching_paths_after_filtering(self) -> None:
        """Test fix with no matching paths after filtering returns empty FixResult."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.js").write_text("const x = 1;\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.js"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            fix_result = formatter.fix(context)
            assert fix_result.issues_fixed == 0
            assert fix_result.issues_remaining == 0

    def test_fix_subprocess_exception_during_run(self) -> None:
        """Test fix handles subprocess exception during ruff format run."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "test.py").write_text("x=1\n")

            formatter = RuffFormatter(project_root=project_root)
            context = ScanContext(
                project_root=project_root,
                paths=[project_root / "test.py"],
                enabled_domains=[ToolDomain.FORMATTING],
            )

            with patch(
                "lucidshark.plugins.formatters.ruff_format.run_with_streaming",
                side_effect=RuntimeError("ruff format crashed"),
            ):
                fix_result = formatter.fix(context)
                assert fix_result.issues_fixed == 0
                assert fix_result.files_modified == 0


class TestRuffFormatterGetVersion:
    """Tests for RuffFormatter.get_version()."""

    def test_get_version_success(self) -> None:
        """Test successful version retrieval."""
        formatter = RuffFormatter()
        with (
            patch.object(
                formatter, "ensure_binary", return_value=Path("/usr/bin/ruff")
            ),
            patch(
                "lucidshark.plugins.formatters.ruff_format.get_cli_version",
                return_value="0.4.1",
            ),
        ):
            assert formatter.get_version() == "0.4.1"

    def test_get_version_binary_not_found(self) -> None:
        """Test version returns 'unknown' when binary not found."""
        formatter = RuffFormatter()
        with patch.object(
            formatter, "ensure_binary", side_effect=FileNotFoundError("not found")
        ):
            assert formatter.get_version() == "unknown"


class TestRuffFormatterResolvePaths:
    """Tests for RuffFormatter path resolution via _resolve_paths."""

    def test_filter_python_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            py_file = root / "test.py"
            py_file.touch()
            js_file = root / "test.js"
            js_file.touch()

            formatter = RuffFormatter()
            context = ScanContext(
                project_root=root,
                paths=[py_file, js_file],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(
                context, PYTHON_EXTENSIONS, fallback_to_cwd=True
            )
            assert len(result) == 1
            assert str(py_file) in result

    def test_filter_pyi_and_pyw_extensions(self) -> None:
        """Test that .pyi and .pyw files are included by filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pyi_file = root / "stubs.pyi"
            pyi_file.touch()
            pyw_file = root / "gui.pyw"
            pyw_file.touch()

            formatter = RuffFormatter()
            context = ScanContext(
                project_root=root,
                paths=[pyi_file, pyw_file],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(
                context, PYTHON_EXTENSIONS, fallback_to_cwd=True
            )
            assert len(result) == 2
            assert str(pyi_file) in result
            assert str(pyw_file) in result

    def test_filter_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subdir = root / "src"
            subdir.mkdir()

            formatter = RuffFormatter()
            context = ScanContext(
                project_root=root,
                paths=[subdir],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(
                context, PYTHON_EXTENSIONS, fallback_to_cwd=True
            )
            assert len(result) == 1
            assert str(subdir) in result
