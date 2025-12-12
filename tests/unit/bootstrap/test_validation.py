"""Tests for tool validation functionality."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from lucidscan.bootstrap.validation import (
    validate_tools,
    validate_tool,
    ToolValidationResult,
    ToolStatus,
)
from lucidscan.bootstrap.paths import LucidscanPaths


class TestToolStatus:
    """Tests for ToolStatus enum."""

    def test_status_values(self) -> None:
        assert ToolStatus.PRESENT.value == "present"
        assert ToolStatus.MISSING.value == "missing"
        assert ToolStatus.NOT_EXECUTABLE.value == "not_executable"


class TestToolValidationResult:
    """Tests for ToolValidationResult dataclass."""

    def test_all_valid_when_all_present(self) -> None:
        result = ToolValidationResult(
            trivy=ToolStatus.PRESENT,
            semgrep=ToolStatus.PRESENT,
            checkov=ToolStatus.PRESENT,
        )
        assert result.all_valid() is True

    def test_all_valid_false_when_missing(self) -> None:
        result = ToolValidationResult(
            trivy=ToolStatus.MISSING,
            semgrep=ToolStatus.PRESENT,
            checkov=ToolStatus.PRESENT,
        )
        assert result.all_valid() is False

    def test_all_valid_false_when_not_executable(self) -> None:
        result = ToolValidationResult(
            trivy=ToolStatus.PRESENT,
            semgrep=ToolStatus.NOT_EXECUTABLE,
            checkov=ToolStatus.PRESENT,
        )
        assert result.all_valid() is False

    def test_missing_tools_returns_list(self) -> None:
        result = ToolValidationResult(
            trivy=ToolStatus.MISSING,
            semgrep=ToolStatus.PRESENT,
            checkov=ToolStatus.NOT_EXECUTABLE,
        )
        missing = result.missing_tools()
        assert "trivy" in missing
        assert "checkov" in missing
        assert "semgrep" not in missing

    def test_to_dict(self) -> None:
        result = ToolValidationResult(
            trivy=ToolStatus.PRESENT,
            semgrep=ToolStatus.MISSING,
            checkov=ToolStatus.NOT_EXECUTABLE,
        )
        d = result.to_dict()
        assert d["trivy"] == "present"
        assert d["semgrep"] == "missing"
        assert d["checkov"] == "not_executable"


class TestValidateTool:
    """Tests for validate_tool function."""

    def test_missing_file(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent"
        status = validate_tool(path)
        assert status == ToolStatus.MISSING

    def test_present_executable(self, tmp_path: Path) -> None:
        path = tmp_path / "tool"
        path.write_text("#!/bin/bash\necho hello")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

        status = validate_tool(path)
        assert status == ToolStatus.PRESENT

    def test_present_not_executable(self, tmp_path: Path) -> None:
        path = tmp_path / "tool"
        path.write_text("#!/bin/bash\necho hello")
        # Remove execute permission
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)

        status = validate_tool(path)
        assert status == ToolStatus.NOT_EXECUTABLE


class TestValidateTools:
    """Tests for validate_tools function."""

    @pytest.fixture
    def paths(self, tmp_path: Path) -> LucidscanPaths:
        home = tmp_path / ".lucidscan"
        return LucidscanPaths(home)

    def test_all_missing_when_not_initialized(self, paths: LucidscanPaths) -> None:
        result = validate_tools(paths)

        assert result.trivy == ToolStatus.MISSING
        assert result.semgrep == ToolStatus.MISSING
        assert result.checkov == ToolStatus.MISSING
        assert result.all_valid() is False

    def test_all_present_when_tools_exist(self, paths: LucidscanPaths) -> None:
        # Create directories and tool files
        paths.ensure_directories()

        # Create trivy
        paths.trivy_bin.write_text("#!/bin/bash\necho trivy")
        paths.trivy_bin.chmod(paths.trivy_bin.stat().st_mode | stat.S_IXUSR)

        # Create semgrep
        paths.semgrep_bin.write_text("#!/bin/bash\necho semgrep")
        paths.semgrep_bin.chmod(paths.semgrep_bin.stat().st_mode | stat.S_IXUSR)

        # Create checkov (needs nested directory)
        paths.checkov_bin.parent.mkdir(parents=True, exist_ok=True)
        paths.checkov_bin.write_text("#!/bin/bash\necho checkov")
        paths.checkov_bin.chmod(paths.checkov_bin.stat().st_mode | stat.S_IXUSR)

        result = validate_tools(paths)

        assert result.trivy == ToolStatus.PRESENT
        assert result.semgrep == ToolStatus.PRESENT
        assert result.checkov == ToolStatus.PRESENT
        assert result.all_valid() is True

    def test_partial_missing(self, paths: LucidscanPaths) -> None:
        paths.ensure_directories()

        # Only create trivy
        paths.trivy_bin.write_text("#!/bin/bash\necho trivy")
        paths.trivy_bin.chmod(paths.trivy_bin.stat().st_mode | stat.S_IXUSR)

        result = validate_tools(paths)

        assert result.trivy == ToolStatus.PRESENT
        assert result.semgrep == ToolStatus.MISSING
        assert result.checkov == ToolStatus.MISSING
        assert result.all_valid() is False
        assert "semgrep" in result.missing_tools()
        assert "checkov" in result.missing_tools()

    def test_not_executable(self, paths: LucidscanPaths) -> None:
        paths.ensure_directories()

        # Create trivy without execute permission
        paths.trivy_bin.write_text("#!/bin/bash\necho trivy")
        paths.trivy_bin.chmod(stat.S_IRUSR | stat.S_IWUSR)  # No execute

        result = validate_tools(paths)

        assert result.trivy == ToolStatus.NOT_EXECUTABLE
        assert result.all_valid() is False
        assert "trivy" in result.missing_tools()

