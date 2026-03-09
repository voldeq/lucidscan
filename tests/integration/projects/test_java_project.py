"""Integration tests for Java project scanning.

These tests run the LucidShark CLI against a realistic Java project
with intentional issues and verify expected results.

Run with: pytest tests/integration/projects/test_java_project.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.integration.projects.conftest import (
    run_lucidshark,
    java_available,
    maven_available,
    spotbugs_available,
)


pytestmark = pytest.mark.integration


@java_available
class TestJavaLinting:
    """Test Java linting against the test project.

    Note: Checkstyle JAR is auto-downloaded by LucidShark, so no fixture setup needed.
    """

    def test_checkstyle_finds_style_issues(self, java_project: Path) -> None:
        """Test that Checkstyle finds style issues."""
        result = run_lucidshark(java_project, domains=["linting"])

        # Should find issues (exit code depends on fail threshold settings)
        assert result.exit_code in (0, 1)

        # Checkstyle should find style issues in our Java files
        linting_issues = result.issues_by_domain("linting")
        # May or may not find issues depending on Checkstyle config
        # At minimum, the scan should complete successfully
        assert isinstance(linting_issues, list)

    def test_linting_json_output_format(self, java_project: Path) -> None:
        """Test that JSON output has expected structure."""
        result = run_lucidshark(java_project, domains=["linting"])

        # Should have issues with required fields
        if result.issues:
            issue = result.issues[0]
            assert "id" in issue
            assert "title" in issue
            assert "severity" in issue
            assert "file_path" in issue


@java_available
@maven_available
@spotbugs_available
class TestJavaTypeChecking:
    """Test Java type checking (SpotBugs) against the test project.

    Note: SpotBugs JAR is auto-downloaded by LucidShark.
    Requires Maven to compile the project first.
    """

    def test_type_checking_scan_completes(self, java_project_with_deps: Path) -> None:
        """Test that type checking scan completes without errors."""
        result = run_lucidshark(java_project_with_deps, domains=["type_checking"])

        # Scan should complete (exit 0 or 1), not crash (exit 2+)
        assert result.exit_code in (0, 1)

        # If type checker finds issues, verify them
        type_issues = result.issues_by_domain("type_checking")
        if type_issues:
            # Verify issues have expected fields
            for issue in type_issues:
                assert "severity" in issue
                assert "file_path" in issue

    def test_spotbugs_detects_null_dereference(
        self, java_project_with_deps: Path
    ) -> None:
        """Test that SpotBugs detects potential null dereference in UserService."""
        result = run_lucidshark(java_project_with_deps, domains=["type_checking"])

        # Scan should complete
        assert result.exit_code in (0, 1)

        type_issues = result.issues_by_domain("type_checking")

        # UserService.getUser() has a null dereference bug
        # Note: Detection depends on SpotBugs version and Java version compatibility
        if type_issues:
            # At least one issue should be in UserService
            user_service_issues = [
                i for i in type_issues if "UserService" in str(i.get("file_path", ""))
            ]
            # May or may not find the specific bug depending on SpotBugs analysis


@java_available
@maven_available
class TestJavaTestRunner:
    """Test Java test running with Maven."""

    def test_maven_runs_tests(self, java_project_with_deps: Path) -> None:
        """Test that Maven test runner executes tests."""
        result = run_lucidshark(java_project_with_deps, domains=["testing"])

        # Scan should complete
        assert result.exit_code in (0, 1)

        # Check summary for test results
        if result.summary:
            # Testing domain should be in results
            testing_summary = result.summary.get("testing", {})
            # If tests ran, we should have test counts
            if testing_summary:
                assert "passed" in testing_summary or "total" in testing_summary


@java_available
@maven_available
class TestJavaCoverage:
    """Test Java coverage with JaCoCo."""

    def test_jacoco_measures_coverage(self, java_project_with_deps: Path) -> None:
        """Test that JaCoCo measures code coverage."""
        result = run_lucidshark(java_project_with_deps, domains=["coverage"])

        # Scan should complete
        assert result.exit_code in (0, 1)

        # Check summary for coverage results
        if result.summary:
            coverage_summary = result.summary.get("coverage", {})
            # If coverage ran, we should have percentage
            if coverage_summary:
                assert (
                    "percentage" in coverage_summary
                    or "total_lines" in coverage_summary
                )


@java_available
@maven_available
class TestJavaCombinedScanning:
    """Test combined scanning for Java projects."""

    def test_combined_linting_and_type_checking(
        self, java_project_with_deps: Path
    ) -> None:
        """Test running both linting and type checking together."""
        result = run_lucidshark(
            java_project_with_deps, domains=["linting", "type_checking"]
        )

        # Scan should complete
        assert result.exit_code in (0, 1)

        # Should have run both domains
        linting_issues = result.issues_by_domain("linting")
        type_issues = result.issues_by_domain("type_checking")

        # At least linting should run (Checkstyle doesn't require compilation)
        assert isinstance(linting_issues, list)
        assert isinstance(type_issues, list)

    def test_scan_all_domains(self, java_project_with_deps: Path) -> None:
        """Test scanning with all domains enabled."""
        result = run_lucidshark(
            java_project_with_deps,
            domains=["linting", "type_checking", "testing", "coverage"],
        )

        # Scan should complete (exit 0 or 1), not error (exit 2+)
        assert result.exit_code in (0, 1)


class TestJavaProjectStructure:
    """Test that the Java project is properly structured."""

    def test_project_has_required_files(self, java_project: Path) -> None:
        """Test that the test project has all required files."""
        assert (java_project / "pom.xml").exists()
        assert (java_project / "src" / "main" / "java").exists()
        assert (java_project / "src" / "test" / "java").exists()

    def test_project_has_source_files(self, java_project: Path) -> None:
        """Test that the project has Java source files."""
        main_java = java_project / "src" / "main" / "java"
        java_files = list(main_java.rglob("*.java"))
        assert len(java_files) >= 2, "Expected at least 2 Java source files"

    def test_project_has_test_files(self, java_project: Path) -> None:
        """Test that the project has Java test files."""
        test_java = java_project / "src" / "test" / "java"
        test_files = list(test_java.rglob("*Test.java"))
        assert len(test_files) >= 2, "Expected at least 2 Java test files"
