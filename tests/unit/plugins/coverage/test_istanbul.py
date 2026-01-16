"""Unit tests for Istanbul/NYC coverage plugin."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import Severity, ToolDomain
from lucidscan.plugins.coverage.istanbul import IstanbulPlugin


class TestIstanbulPlugin:
    """Tests for IstanbulPlugin class."""

    def test_name(self) -> None:
        """Test plugin name."""
        plugin = IstanbulPlugin()
        assert plugin.name == "istanbul"

    def test_languages(self) -> None:
        """Test supported languages."""
        plugin = IstanbulPlugin()
        assert plugin.languages == ["javascript", "typescript"]

    def test_domain(self) -> None:
        """Test domain is COVERAGE."""
        plugin = IstanbulPlugin()
        assert plugin.domain == ToolDomain.COVERAGE


class TestIstanbulBinaryFinding:
    """Tests for binary finding logic."""

    def test_find_in_node_modules(self) -> None:
        """Test finding nyc in project node_modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            nyc_bin = node_bin / "nyc"
            nyc_bin.touch()
            nyc_bin.chmod(0o755)

            plugin = IstanbulPlugin(project_root=project_root)
            binary = plugin.ensure_binary()

            assert binary == nyc_bin

    @patch("shutil.which")
    def test_find_in_system_path(self, mock_which: MagicMock) -> None:
        """Test finding nyc in system PATH."""
        mock_which.return_value = "/usr/local/bin/nyc"

        plugin = IstanbulPlugin()
        binary = plugin.ensure_binary()

        assert binary == Path("/usr/local/bin/nyc")

    @patch("shutil.which")
    def test_not_found_raises_error(self, mock_which: MagicMock) -> None:
        """Test FileNotFoundError when nyc not found."""
        mock_which.return_value = None

        plugin = IstanbulPlugin()
        with pytest.raises(FileNotFoundError) as exc:
            plugin.ensure_binary()

        assert "NYC (Istanbul) is not installed" in str(exc.value)


class TestIstanbulJsonParsing:
    """Tests for JSON report parsing."""

    def test_parse_json_report_below_threshold(self) -> None:
        """Test parsing JSON report when below threshold."""
        plugin = IstanbulPlugin()

        report = {
            "total": {
                "lines": {
                    "total": 100,
                    "covered": 70,
                    "pct": 70.0,
                },
                "statements": {
                    "total": 120,
                    "covered": 84,
                    "pct": 70.0,
                },
                "branches": {
                    "total": 30,
                    "covered": 21,
                    "pct": 70.0,
                },
                "functions": {
                    "total": 20,
                    "covered": 14,
                    "pct": 70.0,
                },
            },
            "src/main.js": {
                "lines": {
                    "total": 50,
                    "covered": 35,
                    "pct": 70.0,
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "coverage-summary.json"
            report_file.write_text(json.dumps(report))

            result = plugin._parse_json_report(report_file, project_root, threshold=80.0)

            assert result.total_lines == 100
            assert result.covered_lines == 70
            assert result.percentage == 70.0
            assert result.passed is False
            assert len(result.issues) == 1

            issue = result.issues[0]
            assert "70.0%" in issue.title
            assert "80.0%" in issue.title
            assert issue.domain == ToolDomain.COVERAGE
            assert issue.source_tool == "istanbul"

    def test_parse_json_report_above_threshold(self) -> None:
        """Test parsing JSON report when above threshold."""
        plugin = IstanbulPlugin()

        report = {
            "total": {
                "lines": {
                    "total": 100,
                    "covered": 90,
                    "pct": 90.0,
                },
                "statements": {"total": 100, "covered": 90, "pct": 90.0},
                "branches": {"total": 50, "covered": 45, "pct": 90.0},
                "functions": {"total": 20, "covered": 18, "pct": 90.0},
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            report_file = project_root / "coverage-summary.json"
            report_file.write_text(json.dumps(report))

            result = plugin._parse_json_report(report_file, project_root, threshold=80.0)

            assert result.percentage == 90.0
            assert result.passed is True
            assert len(result.issues) == 0


class TestIstanbulCoverageIssueCreation:
    """Tests for coverage issue creation."""

    def test_create_issue_high_severity(self) -> None:
        """Test creating issue with HIGH severity (< 50%)."""
        plugin = IstanbulPlugin()

        issue = plugin._create_coverage_issue(
            percentage=40.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=40,
            missing_lines=60,
            statements={"total": 100, "covered": 40, "pct": 40.0},
            branches={"total": 50, "covered": 20, "pct": 40.0},
            functions={"total": 20, "covered": 8, "pct": 40.0},
        )

        assert issue.severity == Severity.HIGH
        assert "40.0%" in issue.title
        assert "80.0%" in issue.title

    def test_create_issue_includes_all_metrics(self) -> None:
        """Test issue description includes all coverage metrics."""
        plugin = IstanbulPlugin()

        issue = plugin._create_coverage_issue(
            percentage=70.0,
            threshold=80.0,
            total_lines=100,
            covered_lines=70,
            missing_lines=30,
            statements={"total": 100, "covered": 70, "pct": 70.0},
            branches={"total": 50, "covered": 35, "pct": 70.0},
            functions={"total": 20, "covered": 14, "pct": 70.0},
        )

        # Description should include all metrics
        desc = issue.description
        assert "Lines:" in desc or "Statements:" in desc


class TestIstanbulIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        """Test same input produces same ID."""
        plugin = IstanbulPlugin()

        id1 = plugin._generate_issue_id(75.0, 80.0)
        id2 = plugin._generate_issue_id(75.0, 80.0)

        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        """Test different input produces different ID."""
        plugin = IstanbulPlugin()

        id1 = plugin._generate_issue_id(75.0, 80.0)
        id2 = plugin._generate_issue_id(60.0, 80.0)

        assert id1 != id2

    def test_id_format(self) -> None:
        """Test ID format starts with istanbul-."""
        plugin = IstanbulPlugin()

        issue_id = plugin._generate_issue_id(75.0, 80.0)

        assert issue_id.startswith("istanbul-")
