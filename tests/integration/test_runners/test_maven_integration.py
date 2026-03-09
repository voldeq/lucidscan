"""Integration tests for Maven test runner plugin.

These tests actually run Maven tests against real Java targets.
They require Java and Maven to be installed.

Run with: pytest tests/integration/test_runners/test_maven_integration.py -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from lucidshark.core.models import ScanContext, ToolDomain
from lucidshark.plugins.test_runners.maven import MavenTestRunner
from tests.integration.conftest import maven_available


class TestMavenAvailability:
    """Tests for Maven availability."""

    @maven_available
    def test_ensure_binary_finds_maven(self, maven_runner: MavenTestRunner) -> None:
        """Test that ensure_binary finds Maven if installed."""
        binary_path = maven_runner.ensure_binary()
        assert binary_path.exists()
        assert "mvn" in binary_path.name

    @maven_available
    def test_get_version(self, maven_runner: MavenTestRunner) -> None:
        """Test that get_version returns a version string."""
        version = maven_runner.get_version()
        assert version != "unknown"
        # Version should be like "3.9.6"
        assert "." in version


@maven_available
class TestMavenFunctional:
    """Functional integration tests for Maven test runner."""

    def test_run_tests_java_webapp(
        self, maven_runner: MavenTestRunner, java_webapp_project: Path
    ) -> None:
        """Test running tests in the java-webapp project."""
        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        result = maven_runner.run_tests(context)

        # Should run the tests
        assert result.total > 0
        # All tests in java-webapp should pass
        assert result.passed > 0
        assert result.success is True

    def test_run_tests_detects_pom_xml(
        self, maven_runner: MavenTestRunner, java_webapp_project: Path
    ) -> None:
        """Test that Maven runner detects pom.xml."""
        pom_file = java_webapp_project / "pom.xml"
        assert pom_file.exists()

        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        result = maven_runner.run_tests(context)

        # Should have run tests
        assert result.total >= 0
        assert result.tool == "maven"

    def test_run_tests_no_pom(self, maven_runner: MavenTestRunner) -> None:
        """Test running tests in project without pom.xml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            context = ScanContext(
                project_root=project_root,
                paths=[project_root],
                enabled_domains=[],
            )

            result = maven_runner.run_tests(context)

            # No tests should be found
            assert result.total == 0
            # Should be marked as success (no failures)
            assert result.success is True


@maven_available
class TestMavenIssueGeneration:
    """Tests for Maven test failure issue generation."""

    def test_run_tests_returns_test_result(
        self, maven_runner: MavenTestRunner, java_webapp_project: Path
    ) -> None:
        """Test that run_tests returns a proper TestResult."""
        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        result = maven_runner.run_tests(context)

        # Check TestResult fields
        assert result.tool == "maven"
        assert result.total >= 0
        assert result.passed >= 0
        assert result.failed >= 0
        assert result.skipped >= 0
        assert isinstance(result.success, bool)
        assert isinstance(result.issues, list)

    def test_test_results_have_correct_domain(
        self, maven_runner: MavenTestRunner, java_webapp_project: Path
    ) -> None:
        """Test that any issues have the correct domain."""
        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        result = maven_runner.run_tests(context)

        # If there are issues, they should have correct domain
        for issue in result.issues:
            assert issue.domain == ToolDomain.TESTING
            assert issue.source_tool == "maven"


@maven_available
class TestMavenXmlParsing:
    """Tests for JUnit XML report parsing."""

    def test_surefire_reports_generated(
        self, maven_runner: MavenTestRunner, java_webapp_project: Path
    ) -> None:
        """Test that Maven generates surefire reports."""
        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        result = maven_runner.run_tests(context)

        # After running tests, surefire reports should exist
        surefire_dir = java_webapp_project / "target" / "surefire-reports"

        # Only check if tests were actually run
        if result.total > 0:
            assert surefire_dir.exists(), (
                "Maven should create surefire-reports directory"
            )

            # Check for XML report files
            xml_files = list(surefire_dir.glob("TEST-*.xml"))
            assert len(xml_files) > 0, "Maven should generate JUnit XML reports"
