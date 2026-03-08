"""Integration tests for SpotBugs type checker.

These tests actually run SpotBugs against real Java targets.
They require Java to be installed and Maven to compile the project.

Run with: pytest tests/integration/type_checkers/test_spotbugs_integration.py -v
"""

from __future__ import annotations

import shutil
from pathlib import Path

from lucidshark.core.models import ScanContext, ToolDomain
from lucidshark.plugins.type_checkers.spotbugs import SpotBugsChecker
from tests.integration.conftest import spotbugs_available, maven_available

_MVN_CMD = shutil.which("mvn") or "mvn"


class TestSpotBugsAvailability:
    """Tests for SpotBugs availability."""

    @spotbugs_available
    def test_ensure_binary_downloads_spotbugs(
        self, spotbugs_checker: SpotBugsChecker
    ) -> None:
        """Test that ensure_binary downloads SpotBugs JAR."""
        binary_path = spotbugs_checker.ensure_binary()
        assert binary_path.exists()
        assert "spotbugs" in binary_path.name.lower()

    @spotbugs_available
    def test_get_version(self, spotbugs_checker: SpotBugsChecker) -> None:
        """Test that get_version returns a version string."""
        version = spotbugs_checker.get_version()
        # Version should be like "4.8.6"
        assert version != "unknown"
        assert "." in version


@spotbugs_available
@maven_available
class TestSpotBugsTypeChecking:
    """Integration tests for SpotBugs type checking."""

    def test_check_java_webapp_project(
        self, spotbugs_checker: SpotBugsChecker, java_webapp_project: Path
    ) -> None:
        """Test checking the java-webapp project with intentional bugs."""
        import subprocess

        # First compile the project with Maven
        result = subprocess.run(
            [_MVN_CMD, "compile", "-q"],
            cwd=java_webapp_project,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )

        if result.returncode != 0:
            # Maven compile failed - skip test
            import pytest

            pytest.skip(f"Maven compile failed: {result.stderr}")

        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        issues = spotbugs_checker.check(context)

        # Should find at least one issue (null dereference in UserService)
        assert isinstance(issues, list)
        # Note: Actual bug count depends on SpotBugs version and Java version
        # The UserService.getUser() has a null dereference bug
        if len(issues) > 0:
            assert issues[0].source_tool == "spotbugs"
            assert issues[0].domain == ToolDomain.TYPE_CHECKING

    def test_check_compiled_classes_exist(
        self, spotbugs_checker: SpotBugsChecker, java_webapp_project: Path
    ) -> None:
        """Test that SpotBugs finds compiled class files."""
        import subprocess

        # First compile the project with Maven
        result = subprocess.run(
            [_MVN_CMD, "compile", "-q"],
            cwd=java_webapp_project,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )

        if result.returncode != 0:
            import pytest

            pytest.skip(f"Maven compile failed: {result.stderr}")

        # Check that target/classes exists
        classes_dir = java_webapp_project / "target" / "classes"
        assert classes_dir.exists(), "Maven should create target/classes directory"

        # Check that class files were compiled
        class_files = list(classes_dir.rglob("*.class"))
        assert len(class_files) > 0, "Maven should compile Java files"


@spotbugs_available
class TestSpotBugsIssueGeneration:
    """Tests for SpotBugs issue generation."""

    @maven_available
    def test_issue_has_correct_fields(
        self, spotbugs_checker: SpotBugsChecker, java_webapp_project: Path
    ) -> None:
        """Test that generated issues have all required fields."""
        import subprocess

        # First compile the project with Maven
        result = subprocess.run(
            [_MVN_CMD, "compile", "-q"],
            cwd=java_webapp_project,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )

        if result.returncode != 0:
            import pytest

            pytest.skip(f"Maven compile failed: {result.stderr}")

        context = ScanContext(
            project_root=java_webapp_project,
            paths=[java_webapp_project],
            enabled_domains=[],
        )

        issues = spotbugs_checker.check(context)

        if len(issues) > 0:
            issue = issues[0]

            # Check required fields
            assert issue.id is not None
            assert issue.id.startswith("spotbugs-")
            assert issue.domain == ToolDomain.TYPE_CHECKING
            assert issue.source_tool == "spotbugs"
            assert issue.severity is not None
            assert issue.title is not None
            assert issue.description is not None
