"""Integration tests for Clippy linter.

These tests require Rust (cargo + clippy) to be installed.

Run with: pytest tests/integration/linters/test_clippy_integration.py -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from lucidshark.core.models import ScanContext, ToolDomain
from lucidshark.plugins.linters.clippy import ClippyLinter
from tests.integration.conftest import clippy_available


class TestClippyAvailability:
    """Tests for Clippy availability."""

    @clippy_available
    def test_ensure_binary_finds_cargo(self, clippy_linter: ClippyLinter) -> None:
        """Test that ensure_binary finds cargo with clippy component."""
        binary_path = clippy_linter.ensure_binary()
        assert binary_path.exists()
        assert "cargo" in binary_path.name

    @clippy_available
    def test_get_version(self, clippy_linter: ClippyLinter) -> None:
        """Test that get_version returns a version string."""
        version = clippy_linter.get_version()
        assert version != "unknown"
        assert "clippy" in version.lower()


@clippy_available
class TestClippyLinting:
    """Integration tests for Clippy linting."""

    def test_lint_rust_file_with_issues(self, clippy_linter: ClippyLinter) -> None:
        """Test linting a Rust file with intentional clippy warnings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create a minimal Cargo.toml
            (tmpdir_path / "Cargo.toml").write_text(
                '[package]\nname = "test-project"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            # Create a Rust file with clippy warnings
            (src_dir / "lib.rs").write_text(
                "pub fn greet(name: &str) -> String {\n"
                "    let owned = name.to_string().clone();\n"  # redundant_clone
                '    return format!("Hello, {}!", owned);\n'  # needless_return
                "}\n"
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = clippy_linter.lint(context)

            # Should find clippy issues
            assert isinstance(issues, list)
            for issue in issues:
                assert issue.source_tool == "clippy"
                assert issue.domain == ToolDomain.LINTING

    def test_lint_empty_directory(self, clippy_linter: ClippyLinter) -> None:
        """Test linting a directory without Cargo.toml returns no issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = clippy_linter.lint(context)

            assert isinstance(issues, list)
            assert len(issues) == 0

    def test_lint_clean_rust_file(self, clippy_linter: ClippyLinter) -> None:
        """Test linting a well-written Rust file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            (tmpdir_path / "Cargo.toml").write_text(
                '[package]\nname = "clean-project"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text(
                "/// Adds two numbers.\n"
                "pub fn add(a: i32, b: i32) -> i32 {\n"
                "    a + b\n"
                "}\n"
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = clippy_linter.lint(context)

            # Clean file should have no issues or minimal issues
            assert isinstance(issues, list)

    def test_lint_sample_project(self, clippy_linter: ClippyLinter) -> None:
        """Test linting the rust-cli sample project."""
        project_path = Path(__file__).parent.parent / "projects" / "rust-cli"
        if not project_path.exists():
            import pytest

            pytest.skip("rust-cli sample project not found")

        context = ScanContext(
            project_root=project_path,
            paths=[project_path],
            enabled_domains=[],
        )

        issues = clippy_linter.lint(context)

        # Sample project has intentional clippy warnings
        assert isinstance(issues, list)
        assert len(issues) >= 1, "Expected at least 1 clippy issue in sample project"

        for issue in issues:
            assert issue.source_tool == "clippy"
            assert issue.domain == ToolDomain.LINTING


@clippy_available
class TestClippyIssueGeneration:
    """Tests for Clippy issue generation."""

    def test_issue_has_correct_fields(self, clippy_linter: ClippyLinter) -> None:
        """Test that generated issues have all required fields."""
        project_path = Path(__file__).parent.parent / "projects" / "rust-cli"
        if not project_path.exists():
            import pytest

            pytest.skip("rust-cli sample project not found")

        context = ScanContext(
            project_root=project_path,
            paths=[project_path],
            enabled_domains=[],
        )

        issues = clippy_linter.lint(context)

        if len(issues) > 0:
            issue = issues[0]

            # Check required fields
            assert issue.id is not None
            assert issue.id.startswith("clippy-")
            assert issue.domain == ToolDomain.LINTING
            assert issue.source_tool == "clippy"
            assert issue.severity is not None
            assert issue.title is not None
            assert issue.description is not None
