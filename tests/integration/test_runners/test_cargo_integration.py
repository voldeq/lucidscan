"""Integration tests for cargo test runner plugin.

These tests actually run cargo test against real Rust targets.
They require Rust (cargo) to be installed.

Run with: pytest tests/integration/test_runners/test_cargo_integration.py -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from lucidshark.core.models import ScanContext, ToolDomain
from lucidshark.plugins.test_runners.cargo import CargoTestRunner
from tests.integration.conftest import cargo_available


class TestCargoAvailability:
    """Tests for cargo availability."""

    @cargo_available
    def test_ensure_binary_finds_cargo(
        self, cargo_test_runner: CargoTestRunner
    ) -> None:
        """Test that ensure_binary finds cargo if installed."""
        binary_path = cargo_test_runner.ensure_binary()
        assert binary_path.exists()
        assert "cargo" in binary_path.name

    @cargo_available
    def test_get_version(self, cargo_test_runner: CargoTestRunner) -> None:
        """Test that get_version returns a version string."""
        version = cargo_test_runner.get_version()
        assert version != "unknown"
        assert "cargo" in version.lower()


@cargo_available
class TestCargoFunctional:
    """Functional integration tests for cargo test runner."""

    def test_run_tests_sample_project(self, cargo_test_runner: CargoTestRunner) -> None:
        """Test running tests in the rust-cli sample project."""
        project_path = Path(__file__).parent.parent / "projects" / "rust-cli"
        if not project_path.exists():
            import pytest

            pytest.skip("rust-cli sample project not found")

        context = ScanContext(
            project_root=project_path,
            paths=[project_path],
            enabled_domains=[],
        )

        result = cargo_test_runner.run_tests(context)

        # Should run the tests
        assert result.total > 0
        # All tests in rust-cli should pass
        assert result.passed > 0
        assert result.success is True

    def test_run_tests_with_passing_tests(
        self, cargo_test_runner: CargoTestRunner
    ) -> None:
        """Test running a Rust project where all tests pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            (tmpdir_path / "Cargo.toml").write_text(
                '[package]\nname = "test-project"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text(
                "pub fn add(a: i32, b: i32) -> i32 { a + b }\n\n"
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    use super::*;\n\n"
                "    #[test]\n"
                "    fn test_add() {\n"
                "        assert_eq!(add(2, 3), 5);\n"
                "    }\n\n"
                "    #[test]\n"
                "    fn test_add_negative() {\n"
                "        assert_eq!(add(-1, 1), 0);\n"
                "    }\n"
                "}\n"
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            result = cargo_test_runner.run_tests(context)

            assert result.passed >= 2
            assert result.failed == 0
            assert result.success is True
            assert result.tool == "cargo"

    def test_run_tests_no_cargo_toml(self, cargo_test_runner: CargoTestRunner) -> None:
        """Test running tests in project without Cargo.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            context = ScanContext(
                project_root=project_root,
                paths=[project_root],
                enabled_domains=[],
            )

            result = cargo_test_runner.run_tests(context)

            # No tests should be found
            assert result.total == 0
            assert result.success is True


@cargo_available
class TestCargoIssueGeneration:
    """Tests for cargo test failure issue generation."""

    def test_run_tests_returns_test_result(
        self, cargo_test_runner: CargoTestRunner
    ) -> None:
        """Test that run_tests returns a proper TestResult."""
        project_path = Path(__file__).parent.parent / "projects" / "rust-cli"
        if not project_path.exists():
            import pytest

            pytest.skip("rust-cli sample project not found")

        context = ScanContext(
            project_root=project_path,
            paths=[project_path],
            enabled_domains=[],
        )

        result = cargo_test_runner.run_tests(context)

        # Check TestResult fields
        assert result.tool == "cargo"
        assert result.total >= 0
        assert result.passed >= 0
        assert result.failed >= 0
        assert result.skipped >= 0
        assert isinstance(result.success, bool)
        assert isinstance(result.issues, list)

    def test_test_results_have_correct_domain(
        self, cargo_test_runner: CargoTestRunner
    ) -> None:
        """Test that any issues have the correct domain."""
        project_path = Path(__file__).parent.parent / "projects" / "rust-cli"
        if not project_path.exists():
            import pytest

            pytest.skip("rust-cli sample project not found")

        context = ScanContext(
            project_root=project_path,
            paths=[project_path],
            enabled_domains=[],
        )

        result = cargo_test_runner.run_tests(context)

        # If there are issues, they should have correct domain
        for issue in result.issues:
            assert issue.domain == ToolDomain.TESTING
            assert issue.source_tool == "cargo"
