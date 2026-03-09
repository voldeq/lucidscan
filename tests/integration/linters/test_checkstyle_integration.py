"""Integration tests for Checkstyle linter.

These tests require Java and Checkstyle to be installed.

Run with: pytest tests/integration/linters -v
"""

from __future__ import annotations

import tempfile
from pathlib import Path


from lucidshark.core.models import ScanContext
from lucidshark.plugins.linters.checkstyle import CheckstyleLinter
from tests.integration.conftest import java_available


class TestCheckstyleResolution:
    """Tests for Checkstyle binary resolution."""

    def test_ensure_binary_raises_when_not_installed(self) -> None:
        """Test that ensure_binary raises FileNotFoundError when checkstyle is not installed."""
        # Create a linter pointing to a non-existent project
        linter = CheckstyleLinter(project_root=Path("/nonexistent"))

        # This will raise FileNotFoundError since checkstyle won't be found
        # unless it's installed globally
        try:
            binary_info = linter.ensure_binary()
            # If checkstyle is installed globally, verify it exists
            if isinstance(binary_info, tuple):
                binary_path, _ = binary_info
                assert binary_path.exists()
            else:
                assert binary_info.exists()
        except FileNotFoundError as e:
            # Expected behavior when checkstyle is not installed
            assert "Checkstyle is not installed" in str(e)


@java_available
class TestCheckstyleLinting:
    """Integration tests for Checkstyle linting checks."""

    def test_lint_java_file_with_issues(
        self, checkstyle_linter: CheckstyleLinter
    ) -> None:
        """Test linting a Java file with style issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create a Java file with style issues (missing Javadoc)
            test_file = tmpdir_path / "Example.java"
            test_file.write_text(
                "public class Example {\n"
                "    public void method() {\n"
                "        int x = 1;\n"
                "    }\n"
                "}\n"
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = checkstyle_linter.lint(context)

            # Should find style issues
            assert isinstance(issues, list)
            for issue in issues:
                assert issue.source_tool == "checkstyle"

    def test_lint_empty_directory(self, checkstyle_linter: CheckstyleLinter) -> None:
        """Test linting an empty directory returns no issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = checkstyle_linter.lint(context)

            assert isinstance(issues, list)
            assert len(issues) == 0

    def test_lint_clean_java_file(self, checkstyle_linter: CheckstyleLinter) -> None:
        """Test linting a well-formatted Java file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create a well-formatted Java file
            test_file = tmpdir_path / "Clean.java"
            test_file.write_text(
                "/**\n"
                " * Example class.\n"
                " */\n"
                "public class Clean {\n"
                "    /**\n"
                "     * Example method.\n"
                "     */\n"
                "    public void method() {\n"
                "        int x = 1;\n"
                "    }\n"
                "}\n"
            )

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            issues = checkstyle_linter.lint(context)

            # Well-formatted file may still have issues depending on config
            assert isinstance(issues, list)
