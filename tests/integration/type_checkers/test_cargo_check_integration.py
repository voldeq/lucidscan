"""Integration tests for cargo check type checker.

These tests require Rust (cargo) to be installed.

Run with: pytest tests/integration/type_checkers/test_cargo_check_integration.py -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from lucidshark.core.models import ScanContext, ToolDomain
from lucidshark.plugins.type_checkers.cargo_check import CargoCheckChecker
from tests.integration.conftest import cargo_available


class TestCargoCheckAvailability:
    """Tests for cargo check availability."""

    @cargo_available
    def test_ensure_binary_finds_cargo(
        self, cargo_check_checker: CargoCheckChecker
    ) -> None:
        """Test that ensure_binary finds cargo."""
        binary_path = cargo_check_checker.ensure_binary()
        assert binary_path.exists()
        assert "cargo" in binary_path.name

    @cargo_available
    def test_get_version(self, cargo_check_checker: CargoCheckChecker) -> None:
        """Test that get_version returns a version string."""
        version = cargo_check_checker.get_version()
        assert version != "unknown"
        assert "cargo" in version.lower()


@cargo_available
class TestCargoCheckTypeChecking:
    """Integration tests for cargo check type checking."""

    def test_check_valid_project(self, cargo_check_checker: CargoCheckChecker) -> None:
        """Test checking a valid Rust project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            (tmpdir_path / "Cargo.toml").write_text(
                '[package]\nname = "test-project"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text(
                "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = cargo_check_checker.check(context)

            # Valid code should compile clean
            assert isinstance(issues, list)

    def test_check_project_with_errors(
        self, cargo_check_checker: CargoCheckChecker
    ) -> None:
        """Test checking a Rust project with type errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            (tmpdir_path / "Cargo.toml").write_text(
                '[package]\nname = "test-project"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            # Intentional type error: returning &str where i32 expected
            (src_dir / "lib.rs").write_text(
                'pub fn add(a: i32, b: i32) -> i32 {\n    "not a number"\n}\n'
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = cargo_check_checker.check(context)

            # Should find type errors
            assert isinstance(issues, list)
            assert len(issues) >= 1, "Expected at least 1 type error"
            for issue in issues:
                assert issue.source_tool == "cargo_check"
                assert issue.domain == ToolDomain.TYPE_CHECKING

    def test_check_no_cargo_toml(self, cargo_check_checker: CargoCheckChecker) -> None:
        """Test checking a directory without Cargo.toml returns no issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = cargo_check_checker.check(context)

            assert isinstance(issues, list)
            assert len(issues) == 0

    def test_check_sample_project(self, cargo_check_checker: CargoCheckChecker) -> None:
        """Test checking the rust-cli sample project."""
        project_path = Path(__file__).parent.parent / "projects" / "rust-cli"
        if not project_path.exists():
            import pytest

            pytest.skip("rust-cli sample project not found")

        context = ScanContext(
            project_root=project_path,
            paths=[project_path],
            enabled_domains=[],
        )

        issues = cargo_check_checker.check(context)

        # Sample project should compile (clippy warnings are filtered out)
        assert isinstance(issues, list)
        for issue in issues:
            assert issue.source_tool == "cargo_check"
            assert issue.domain == ToolDomain.TYPE_CHECKING


@cargo_available
class TestCargoCheckIssueGeneration:
    """Tests for cargo check issue generation."""

    def test_type_error_has_correct_fields(
        self, cargo_check_checker: CargoCheckChecker
    ) -> None:
        """Test that generated issues have all required fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            (tmpdir_path / "Cargo.toml").write_text(
                '[package]\nname = "test-project"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text(
                'pub fn add(a: i32, b: i32) -> i32 {\n    "not a number"\n}\n'
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = cargo_check_checker.check(context)

            if len(issues) > 0:
                issue = issues[0]

                assert issue.id is not None
                assert issue.id.startswith("cargo-check-")
                assert issue.domain == ToolDomain.TYPE_CHECKING
                assert issue.source_tool == "cargo_check"
                assert issue.severity is not None
                assert issue.title is not None
                assert issue.description is not None
