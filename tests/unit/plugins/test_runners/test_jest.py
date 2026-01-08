"""Unit tests for Jest runner plugin."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import ToolDomain
from lucidscan.plugins.test_runners.jest import JestRunner


class TestJestRunner:
    """Tests for JestRunner class."""

    def test_name(self) -> None:
        """Test plugin name."""
        runner = JestRunner()
        assert runner.name == "jest"

    def test_languages(self) -> None:
        """Test supported languages."""
        runner = JestRunner()
        assert runner.languages == ["javascript", "typescript"]

    def test_domain(self) -> None:
        """Test domain is TESTING."""
        runner = JestRunner()
        assert runner.domain == ToolDomain.TESTING


class TestJestRunnerBinaryFinding:
    """Tests for binary finding logic."""

    def test_find_in_node_modules(self) -> None:
        """Test finding jest in project node_modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            jest_bin = node_bin / "jest"
            jest_bin.touch()
            jest_bin.chmod(0o755)

            runner = JestRunner(project_root=project_root)
            binary = runner.ensure_binary()

            assert binary == jest_bin

    @patch("shutil.which")
    def test_find_in_system_path(self, mock_which: MagicMock) -> None:
        """Test finding jest in system PATH."""
        mock_which.return_value = "/usr/local/bin/jest"

        runner = JestRunner()
        binary = runner.ensure_binary()

        assert binary == Path("/usr/local/bin/jest")

    @patch("shutil.which")
    def test_not_found_raises_error(self, mock_which: MagicMock) -> None:
        """Test FileNotFoundError when jest not found."""
        mock_which.return_value = None

        runner = JestRunner()
        with pytest.raises(FileNotFoundError) as exc:
            runner.ensure_binary()

        assert "Jest is not installed" in str(exc.value)


class TestJestReportProcessing:
    """Tests for Jest report processing."""

    def test_process_report_with_failures(self) -> None:
        """Test processing Jest report with failures."""
        runner = JestRunner()

        report = {
            "numPassedTests": 5,
            "numFailedTests": 2,
            "numPendingTests": 1,
            "numTodoTests": 0,
            "startTime": 1000,
            "testResults": [
                {
                    "name": "/project/tests/example.test.js",
                    "status": "failed",
                    "startTime": 1000,
                    "endTime": 1500,
                    "assertionResults": [
                        {
                            "fullName": "Example test should pass",
                            "status": "passed",
                            "title": "should pass",
                            "ancestorTitles": ["Example test"],
                        },
                        {
                            "fullName": "Example test should fail",
                            "status": "failed",
                            "title": "should fail",
                            "ancestorTitles": ["Example test"],
                            "failureMessages": ["expect(1).toBe(2)"],
                            "location": {"line": 10},
                        },
                    ],
                },
            ],
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 5
        assert result.failed == 2
        assert result.skipped == 1
        assert len(result.issues) == 1

        issue = result.issues[0]
        assert "should fail" in issue.title
        assert issue.source_tool == "jest"

    def test_process_report_all_passed(self) -> None:
        """Test processing Jest report with all tests passed."""
        runner = JestRunner()

        report = {
            "numPassedTests": 10,
            "numFailedTests": 0,
            "numPendingTests": 0,
            "numTodoTests": 0,
            "testResults": [],
        }

        project_root = Path("/project")
        result = runner._process_report(report, project_root)

        assert result.passed == 10
        assert result.failed == 0
        assert result.success is True
        assert len(result.issues) == 0


class TestJestAssertionExtraction:
    """Tests for assertion message extraction."""

    def test_extract_expect_pattern(self) -> None:
        """Test extracting expect() assertion."""
        runner = JestRunner()

        message = """
expect(received).toBe(expected)

Expected: 2
Received: 1
        """

        result = runner._extract_assertion(message)
        assert "Expected:" in result or "expect" in result.lower()

    def test_empty_message(self) -> None:
        """Test empty message returns empty string."""
        runner = JestRunner()
        result = runner._extract_assertion("")
        assert result == ""


class TestJestIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        runner = JestRunner()

        id1 = runner._generate_issue_id("Test > should work", "expect")
        id2 = runner._generate_issue_id("Test > should work", "expect")

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        runner = JestRunner()

        id1 = runner._generate_issue_id("Test > should work", "expect 1")
        id2 = runner._generate_issue_id("Test > should fail", "expect 2")

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with jest-."""
        runner = JestRunner()

        issue_id = runner._generate_issue_id("Test > should work", "expect")

        assert issue_id.startswith("jest-")
        assert len(issue_id) == len("jest-") + 12  # 12 char hash
