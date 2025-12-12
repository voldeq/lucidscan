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
        assert paths.checkov_env == home / "checkov-env"
        assert paths.cache_dir == home / "cache"
        assert paths.config_dir == home / "config"
        assert paths.logs_dir == home / "logs"

    def test_tool_paths(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        assert paths.trivy_bin == home / "bin" / "trivy"
        assert paths.semgrep_bin == home / "bin" / "semgrep"
        assert paths.checkov_bin == home / "checkov-env" / "bin" / "checkov"

    def test_versions_json_path(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        assert paths.versions_json == home / "config" / "versions.json"

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
        assert paths.checkov_env.exists()
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

    def test_is_initialized_true_when_versions_json_exists(self, tmp_path: Path) -> None:
        home = tmp_path / ".lucidscan"
        paths = LucidscanPaths(home)

        paths.ensure_directories()
        paths.versions_json.write_text('{"version": "1.0.0"}')

        assert paths.is_initialized() is True

    def test_default_factory(self) -> None:
        """Test that default() creates paths from lucidscan home."""
        with patch("lucidscan.bootstrap.paths.get_lucidscan_home") as mock_home:
            mock_home.return_value = Path("/mock/home/.lucidscan")
            paths = LucidscanPaths.default()

            assert paths.home == Path("/mock/home/.lucidscan")
            mock_home.assert_called_once()

