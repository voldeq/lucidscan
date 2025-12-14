"""Tests for path management functionality."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from lucidscan.bootstrap.paths import (
    get_lucidscan_home,
    LucidscanPaths,
    DEFAULT_HOME_DIR_NAME,
)


class TestGetLucidscanHome:
    """Tests for get_lucidscan_home function."""

    def test_returns_default_in_user_home(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=False):
            with patch.dict(os.environ, {"LUCIDSCAN_HOME": ""}, clear=False):
                # Remove LUCIDSCAN_HOME if it exists
                os.environ.pop("LUCIDSCAN_HOME", None)
                home = get_lucidscan_home()
                assert home == tmp_path / DEFAULT_HOME_DIR_NAME

    def test_respects_lucidscan_home_env_var(self, tmp_path: Path) -> None:
        custom_home = tmp_path / "custom-lucidscan"
        with patch.dict(os.environ, {"LUCIDSCAN_HOME": str(custom_home)}):
            home = get_lucidscan_home()
            assert home == custom_home

    def test_returns_path_object(self) -> None:
        home = get_lucidscan_home()
        assert isinstance(home, Path)


class TestLucidscanPaths:
    """Tests for LucidscanPaths class."""

    def test_paths_from_home(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        assert paths.home == home
        assert paths.bin_dir == home / "bin"
        assert paths.cache_dir == home / "cache"
        assert paths.config_dir == home / "config"
        assert paths.logs_dir == home / "logs"

    def test_plugin_bin_dir(self, tmp_path: Path) -> None:
        """Test plugin-specific binary directory structure."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        assert paths.plugin_bin_dir("trivy", "0.68.1") == home / "bin" / "trivy" / "0.68.1"
        assert paths.plugin_bin_dir("opengrep", "1.12.1") == home / "bin" / "opengrep" / "1.12.1"
        assert paths.plugin_bin_dir("checkov", "3.2.495") == home / "bin" / "checkov" / "3.2.495"

    def test_trivy_cache_dir(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        assert paths.trivy_cache == home / "cache" / "trivy"

    def test_ensure_directories_creates_all_dirs(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        # Directories should not exist yet
        assert not paths.home.exists()

        # Create directories
        paths.ensure_directories()

        # All directories should now exist
        assert paths.home.exists()
        assert paths.bin_dir.exists()
        assert paths.cache_dir.exists()
        assert paths.config_dir.exists()
        assert paths.logs_dir.exists()
        assert paths.trivy_cache.exists()

    def test_ensure_directories_is_idempotent(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        # Call multiple times
        paths.ensure_directories()
        paths.ensure_directories()

        # Should still work
        assert paths.home.exists()

    def test_is_initialized_false_when_empty(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        assert paths.is_initialized() is False

    def test_is_initialized_true_when_plugin_installed(self, tmp_path: Path) -> None:
        """Test that is_initialized returns True when a plugin directory exists."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        paths.ensure_directories()
        # Create a plugin directory
        plugin_dir = paths.plugin_bin_dir("trivy", "0.68.1")
        plugin_dir.mkdir(parents=True, exist_ok=True)

        assert paths.is_initialized() is True

    def test_default_factory(self) -> None:
        """Test that default() creates paths from lucidscan home."""
        with patch("lucidscan.bootstrap.paths.get_lucidscan_home") as mock_home:
            mock_home.return_value = Path("/mock/home/.lucidscan")
            paths = LucidscanPaths.default()

            assert paths.home == Path("/mock/home/.lucidscan")
            mock_home.assert_called_once()


class TestToolBinaryPaths:
    """Tests for tool binary path resolution with version directories."""

    def test_trivy_bin_with_version_dir(self, tmp_path: Path) -> None:
        """Test trivy_bin finds binary in version directory."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)
        paths.ensure_directories()

        # Create version directory with binary
        version_dir = paths.bin_dir / "trivy" / "0.68.1"
        version_dir.mkdir(parents=True)
        trivy_bin = version_dir / "trivy"
        trivy_bin.write_text("#!/bin/bash\necho trivy")

        # Should find the binary
        assert paths.trivy_bin == trivy_bin

    def test_trivy_bin_with_current_symlink(self, tmp_path: Path) -> None:
        """Test trivy_bin uses 'current' symlink when present."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)
        paths.ensure_directories()

        # Create version directory
        version_dir = paths.bin_dir / "trivy" / "0.68.1"
        version_dir.mkdir(parents=True)
        trivy_bin = version_dir / "trivy"
        trivy_bin.write_text("#!/bin/bash\necho trivy")

        # Create current symlink
        current_link = paths.bin_dir / "trivy" / "current"
        current_link.symlink_to(version_dir)

        # Should use current symlink
        assert paths.trivy_bin == current_link / "trivy"

    def test_opengrep_bin_with_version_dir(self, tmp_path: Path) -> None:
        """Test opengrep_bin finds binary in version directory."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)
        paths.ensure_directories()

        # Create version directory with binary
        version_dir = paths.bin_dir / "opengrep" / "1.12.1"
        version_dir.mkdir(parents=True)
        opengrep_bin = version_dir / "opengrep"
        opengrep_bin.write_text("#!/bin/bash\necho opengrep")

        # Should find the binary
        assert paths.opengrep_bin == opengrep_bin

    def test_checkov_bin_with_venv_structure(self, tmp_path: Path) -> None:
        """Test checkov_bin finds binary in virtualenv structure."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)
        paths.ensure_directories()

        # Create venv structure
        venv_bin_dir = paths.bin_dir / "checkov" / "3.2.495" / "venv" / "bin"
        venv_bin_dir.mkdir(parents=True)
        checkov_bin = venv_bin_dir / "checkov"
        checkov_bin.write_text("#!/bin/bash\necho checkov")

        # Should find the binary in venv
        assert paths.checkov_bin == checkov_bin

    def test_tool_bin_fallback_path(self, tmp_path: Path) -> None:
        """Test tool bin paths return fallback when not installed."""
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        # Without any installation, should return fallback paths
        assert "trivy" in str(paths.trivy_bin)
        assert "opengrep" in str(paths.opengrep_bin)
        assert "checkov" in str(paths.checkov_bin)
