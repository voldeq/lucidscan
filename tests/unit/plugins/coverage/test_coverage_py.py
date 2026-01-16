"""Unit tests for coverage.py plugin."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import Severity, ToolDomain
from lucidscan.plugins.coverage.coverage_py import CoveragePyPlugin


class TestCoveragePyPlugin:
    """Tests for CoveragePyPlugin class."""

    def test_name(self) -> None:
        """Test plugin name."""
        plugin = CoveragePyPlugin()
        assert plugin.name == "coverage_py"

    def test_languages(self) -> None:
        """Test supported languages."""
        plugin = CoveragePyPlugin()
        assert plugin.languages == ["python"]

    def test_domain(self) -> None:
        """Test domain is COVERAGE."""
        plugin = CoveragePyPlugin()
        assert plugin.domain == ToolDomain.COVERAGE


class TestCoveragePyBinaryFinding:
    """Tests for binary finding logic."""

    def test_find_in_venv(self) -> None:
        """Test finding coverage in project .venv."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            venv_bin = project_root / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            coverage_bin = venv_bin / "coverage"
            coverage_bin.touch()
            coverage_bin.chmod(0o755)

            plugin = CoveragePyPlugin(project_root=project_root)
            binary = plugin.ensure_binary()

            assert binary == coverage_bin

    @patch("shutil.which")
    def test_find_in_system_path(self, mock_which: MagicMock) -> None:
        """Test finding coverage in system PATH."""
        mock_which.return_value = "/usr/local/bin/coverage"

        plugin = CoveragePyPlugin()
        binary = plugin.ensure_binary()

        assert binary == Path("/usr/local/bin/coverage")

    @patch("shutil.which")
    def test_not_found_raises_error(self, mock_which: MagicMock) -> None:
        """Test FileNotFoundError when coverage not found."""
        mock_which.return_value = None

        plugin = CoveragePyPlugin()
        with pytest.raises(FileNotFoundError) as exc:
            plugin.ensure_binary()

        assert "coverage is not installed" in str(exc.value)


class TestCoveragePyJsonParsing:
    """Tests for JSON report parsing."""

    def test_parse_json_report_below_threshold(self) -> None:
        """Test parsing JSON report when below threshold."""
        plugin = CoveragePyPlugin()

        report = {
            "totals": {
                "num_statements": 100,
                "covered_lines": 75,
                "missing_lines": 25,
                "excluded_lines": 0,
                "percent_covered": 75.0,
            },
            "files": {
                "src/main.py": {
                    "summary": {
                        "num_statements": 50,
                        "covered_lines": 35,
                        "excluded_lines": 0,
                    },
                    "missing_lines": [10, 15, 20],
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "coverage.json"
            report_file.write_text(json.dumps(report))

            result = plugin._parse_json_report(report_file, project_root, threshold=80.0)

            assert result.total_lines == 100
            assert result.covered_lines == 75
            assert result.percentage == 75.0
            assert result.passed is False
            assert len(result.issues) == 1

            issue = result.issues[0]
            assert "75.0%" in issue.title
            assert "80.0%" in issue.title
            assert issue.severity in [Severity.LOW, Severity.MEDIUM, Severity.HIGH]
            assert issue.domain == ToolDomain.COVERAGE
            assert issue.source_tool == "coverage.py"

    def test_parse_json_report_above_threshold(self) -> None:
        """Test parsing JSON report when above threshold."""
        plugin = CoveragePyPlugin()

        report = {
            "totals": {
                "num_statements": 100,
                "covered_lines": 90,
                "missing_lines": 10,
                "excluded_lines": 0,
                "percent_covered": 90.0,
            },
            "files": {},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "coverage.json"
            report_file.write_text(json.dumps(report))

            result = plugin._parse_json_report(report_file, project_root, threshold=80.0)

            assert result.percentage == 90.0
            assert result.passed is True
            assert len(result.issues) == 0


class TestCoveragePyCoverageIssueCreation:
    """Tests for coverage issue creation."""

    def test_create_issue_high_severity(self) -> None:
        """Test creating issue with HIGH severity (< 50%)."""
        plugin = CoveragePyPlugin()

        issue = plugin._create_coverage_issue(
            percentage=40.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=40,
            missing_lines=60,
        )

        assert issue.severity == Severity.HIGH
        assert "40.0%" in issue.title
        assert "80.0%" in issue.title

    def test_create_issue_medium_severity(self) -> None:
        """Test creating issue with MEDIUM severity (< threshold - 10)."""
        plugin = CoveragePyPlugin()

        issue = plugin._create_coverage_issue(
            percentage=65.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=65,
            missing_lines=35,
        )

        assert issue.severity == Severity.MEDIUM

    def test_create_issue_low_severity(self) -> None:
        """Test creating issue with LOW severity (close to threshold)."""
        plugin = CoveragePyPlugin()

        issue = plugin._create_coverage_issue(
            percentage=78.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=78,
            missing_lines=22,
        )

        assert issue.severity == Severity.LOW

    def test_issue_metadata(self) -> None:
        """Test issue contains correct metadata."""
        plugin = CoveragePyPlugin()

        issue = plugin._create_coverage_issue(
            percentage=75.0,
            threshold=80.0,
            total_lines=200,
            covered_lines=150,
            missing_lines=50,
        )

        metadata = issue.metadata
        assert metadata["coverage_percentage"] == 75.0
        assert metadata["threshold"] == 80.0
        assert metadata["total_lines"] == 200
        assert metadata["covered_lines"] == 150
        assert metadata["missing_lines"] == 50
        assert metadata["gap_percentage"] == 5.0


class TestCoveragePyIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        plugin = CoveragePyPlugin()

        id1 = plugin._generate_issue_id(75.0, 80.0)
        id2 = plugin._generate_issue_id(75.0, 80.0)

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        plugin = CoveragePyPlugin()

        id1 = plugin._generate_issue_id(75.0, 80.0)
        id2 = plugin._generate_issue_id(60.0, 80.0)

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with coverage-."""
        plugin = CoveragePyPlugin()

        issue_id = plugin._generate_issue_id(75.0, 80.0)

        assert issue_id.startswith("coverage-")
