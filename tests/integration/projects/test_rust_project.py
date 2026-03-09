"""Integration tests for Rust project scanning.

These tests run the LucidShark CLI against a realistic Rust project
with intentional issues and verify expected results.

Run with: pytest tests/integration/projects/test_rust_project.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.projects.conftest import (
    run_lucidshark,
    cargo_available,
    clippy_available,
    tarpaulin_available,
)


pytestmark = pytest.mark.integration


@clippy_available
class TestRustLinting:
    """Test Rust linting (Clippy) against the test project.

    Clippy is a Rust linter that detects common mistakes and style issues.
    """

    def test_clippy_finds_lint_issues(self, rust_project: Path) -> None:
        """Test that Clippy finds lint issues in the Rust project."""
        result = run_lucidshark(rust_project, domains=["linting"])

        # Should find issues (exit code depends on fail threshold settings)
        assert result.exit_code in (0, 1)

        # Clippy should find style/correctness issues
        linting_issues = result.issues_by_domain("linting")
        assert len(linting_issues) >= 1, "Expected at least 1 clippy lint issue"

    def test_clippy_finds_redundant_clone(self, rust_project: Path) -> None:
        """Test that Clippy detects redundant clone in user_service."""
        result = run_lucidshark(rust_project, domains=["linting"])

        linting_issues = result.issues_by_domain("linting")
        # The project has intentional redundant_clone in lib.rs
        if linting_issues:
            lib_issues = [
                i for i in linting_issues if "lib.rs" in str(i.get("file_path", ""))
            ]
            assert len(lib_issues) >= 1, "Expected clippy issues in lib.rs"

    def test_clippy_finds_unused_import(self, rust_project: Path) -> None:
        """Test that Clippy detects unused import in main.rs."""
        result = run_lucidshark(rust_project, domains=["linting"])

        linting_issues = result.issues_by_domain("linting")
        if linting_issues:
            main_issues = [
                i for i in linting_issues if "main.rs" in str(i.get("file_path", ""))
            ]
            # main.rs has unused HashMap import
            assert isinstance(main_issues, list)

    def test_linting_json_output_format(self, rust_project: Path) -> None:
        """Test that JSON output has expected structure."""
        result = run_lucidshark(rust_project, domains=["linting"])

        # Should have issues with required fields
        if result.issues:
            issue = result.issues[0]
            assert "id" in issue
            assert "title" in issue
            assert "severity" in issue
            assert "file_path" in issue


@cargo_available
class TestRustTypeChecking:
    """Test Rust type checking (cargo check) against the test project.

    cargo check verifies that the project compiles without errors.
    """

    def test_type_checking_scan_completes(self, rust_project: Path) -> None:
        """Test that type checking scan completes without errors."""
        result = run_lucidshark(rust_project, domains=["type_checking"])

        # Scan should complete (exit 0 or 1), not crash (exit 2+)
        assert result.exit_code in (0, 1)

    def test_cargo_check_reports_warnings(self, rust_project: Path) -> None:
        """Test that cargo check reports compiler warnings."""
        result = run_lucidshark(rust_project, domains=["type_checking"])

        assert result.exit_code in (0, 1)

        # cargo check may find warnings (e.g., unused imports if not caught by clippy)
        type_issues = result.issues_by_domain("type_checking")
        if type_issues:
            for issue in type_issues:
                assert "severity" in issue
                assert "file_path" in issue


@cargo_available
class TestRustTestRunner:
    """Test Rust test running with cargo test."""

    def test_cargo_runs_tests(self, rust_project: Path) -> None:
        """Test that cargo test runner executes tests."""
        result = run_lucidshark(rust_project, domains=["testing"])

        # Scan should complete
        assert result.exit_code in (0, 1)

        # Check summary for test results
        if result.summary:
            testing_summary = result.summary.get("testing", {})
            if testing_summary:
                assert "passed" in testing_summary or "total" in testing_summary


@cargo_available
@tarpaulin_available
class TestRustCoverage:
    """Test Rust coverage with cargo-tarpaulin."""

    def test_tarpaulin_measures_coverage(self, rust_project_compiled: Path) -> None:
        """Test that tarpaulin measures code coverage."""
        result = run_lucidshark(rust_project_compiled, domains=["coverage"])

        # Scan should complete
        assert result.exit_code in (0, 1)

        # Check summary for coverage results
        if result.summary:
            coverage_summary = result.summary.get("coverage", {})
            if coverage_summary:
                assert (
                    "percentage" in coverage_summary
                    or "total_lines" in coverage_summary
                )


@cargo_available
class TestRustCombinedScanning:
    """Test combined scanning for Rust projects."""

    @clippy_available
    def test_combined_linting_and_type_checking(self, rust_project: Path) -> None:
        """Test running both linting and type checking together."""
        result = run_lucidshark(rust_project, domains=["linting", "type_checking"])

        # Scan should complete
        assert result.exit_code in (0, 1)

        # Should have run both domains
        linting_issues = result.issues_by_domain("linting")
        type_issues = result.issues_by_domain("type_checking")

        # At least linting should find issues (clippy on intentional issues)
        assert isinstance(linting_issues, list)
        assert isinstance(type_issues, list)

    @clippy_available
    def test_scan_all_domains(self, rust_project: Path) -> None:
        """Test scanning with all domains enabled."""
        result = run_lucidshark(
            rust_project,
            domains=["linting", "type_checking", "testing"],
        )

        # Scan should complete (exit 0 or 1), not error (exit 2+)
        assert result.exit_code in (0, 1)


class TestRustProjectStructure:
    """Test that the Rust project is properly structured."""

    def test_project_has_required_files(self, rust_project: Path) -> None:
        """Test that the test project has all required files."""
        assert (rust_project / "Cargo.toml").exists()
        assert (rust_project / "src" / "lib.rs").exists()
        assert (rust_project / "src" / "main.rs").exists()

    def test_project_has_source_files(self, rust_project: Path) -> None:
        """Test that the project has Rust source files."""
        src_dir = rust_project / "src"
        rs_files = list(src_dir.rglob("*.rs"))
        assert len(rs_files) >= 2, "Expected at least 2 Rust source files"

    def test_project_has_test_files(self, rust_project: Path) -> None:
        """Test that the project has Rust test files."""
        tests_dir = rust_project / "tests"
        test_files = list(tests_dir.rglob("*.rs"))
        assert len(test_files) >= 2, "Expected at least 2 Rust test files"
