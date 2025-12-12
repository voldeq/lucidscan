"""Tests for bundle management functionality."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from lucidscan.bootstrap.bundle import (
    BundleManager,
    BundleVersions,
    BundleError,
    DEFAULT_BUNDLE_BASE_URL,
    construct_bundle_url,
)
from lucidscan.bootstrap.paths import LucidscanPaths
from lucidscan.bootstrap.platform import PlatformInfo


class TestBundleVersions:
    """Tests for BundleVersions dataclass."""

    def test_creation(self) -> None:
        versions = BundleVersions(
            lucidscan="0.1.0",
            trivy="0.52.0",
            semgrep="1.80.0",
            checkov="3.2.12",
            bundle_version="2025.01.01",
        )
        assert versions.lucidscan == "0.1.0"
        assert versions.trivy == "0.52.0"

    def test_to_dict(self) -> None:
        versions = BundleVersions(
            lucidscan="0.1.0",
            trivy="0.52.0",
            semgrep="1.80.0",
            checkov="3.2.12",
            bundle_version="2025.01.01",
        )
        d = versions.to_dict()
        assert d["lucidscan"] == "0.1.0"
        assert d["bundleVersion"] == "2025.01.01"

    def test_from_dict(self) -> None:
        data = {
            "lucidscan": "0.2.0",
            "trivy": "0.53.0",
            "semgrep": "1.81.0",
            "checkov": "3.3.0",
            "bundleVersion": "2025.02.01",
        }
        versions = BundleVersions.from_dict(data)
        assert versions.lucidscan == "0.2.0"
        assert versions.bundle_version == "2025.02.01"

    def test_from_dict_with_missing_optional_fields(self) -> None:
        data = {
            "lucidscan": "0.2.0",
        }
        versions = BundleVersions.from_dict(data)
        assert versions.lucidscan == "0.2.0"
        assert versions.trivy == ""
        assert versions.bundle_version == ""


class TestConstructBundleUrl:
    """Tests for bundle URL construction."""

    def test_construct_url_linux_amd64(self) -> None:
        platform_info = PlatformInfo(os="linux", arch="amd64")
        url = construct_bundle_url(platform_info)
        assert "linux-amd64" in url
        assert url.endswith(".tar.gz")

    def test_construct_url_darwin_arm64(self) -> None:
        platform_info = PlatformInfo(os="darwin", arch="arm64")
        url = construct_bundle_url(platform_info)
        assert "darwin-arm64" in url
        assert url.endswith(".tar.gz")

    def test_construct_url_with_custom_base(self) -> None:
        platform_info = PlatformInfo(os="linux", arch="amd64")
        custom_base = "https://internal.example.com/tools"
        url = construct_bundle_url(platform_info, base_url=custom_base)
        assert url.startswith(custom_base)

    def test_construct_url_windows_uses_zip(self) -> None:
        platform_info = PlatformInfo(os="windows", arch="amd64")
        url = construct_bundle_url(platform_info)
        assert "windows-amd64" in url
        assert url.endswith(".zip")


class TestBundleManager:
    """Tests for BundleManager class."""

    @pytest.fixture
    def paths(self, tmp_path: Path) -> LucidscanPaths:
        """Create LucidscanPaths for testing."""
        home = tmp_path / ".lucidscan"
        return LucidscanPaths(home)

    @pytest.fixture
    def platform_info(self) -> PlatformInfo:
        """Create test platform info."""
        return PlatformInfo(os="linux", arch="amd64")

    @pytest.fixture
    def manager(self, paths: LucidscanPaths, platform_info: PlatformInfo) -> BundleManager:
        """Create BundleManager for testing."""
        return BundleManager(paths=paths, platform_info=platform_info)

    def test_needs_bootstrap_true_when_not_initialized(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        assert manager.needs_bootstrap() is True

    def test_needs_bootstrap_false_when_initialized(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        paths.ensure_directories()
        paths.versions_json.write_text('{"lucidscan": "0.1.0"}')
        assert manager.needs_bootstrap() is False

    def test_read_versions_returns_none_when_missing(
        self, manager: BundleManager
    ) -> None:
        assert manager.read_versions() is None

    def test_read_versions_returns_bundle_versions(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        paths.ensure_directories()
        data = {
            "lucidscan": "0.1.0",
            "trivy": "0.52.0",
            "semgrep": "1.80.0",
            "checkov": "3.2.12",
            "bundleVersion": "2025.01.01",
        }
        paths.versions_json.write_text(json.dumps(data))

        versions = manager.read_versions()
        assert versions is not None
        assert versions.trivy == "0.52.0"

    def test_write_versions(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        paths.ensure_directories()
        versions = BundleVersions(
            lucidscan="0.1.0",
            trivy="0.52.0",
            semgrep="1.80.0",
            checkov="3.2.12",
            bundle_version="2025.01.01",
        )
        manager.write_versions(versions)

        content = json.loads(paths.versions_json.read_text())
        assert content["trivy"] == "0.52.0"

    def test_get_bundle_url(self, manager: BundleManager) -> None:
        url = manager.get_bundle_url()
        assert "linux-amd64" in url
        assert url.endswith(".tar.gz")

    def test_get_bundle_url_with_custom_base(
        self, paths: LucidscanPaths, platform_info: PlatformInfo
    ) -> None:
        custom_base = "https://internal.example.com"
        manager = BundleManager(
            paths=paths, platform_info=platform_info, bundle_base_url=custom_base
        )
        url = manager.get_bundle_url()
        assert url.startswith(custom_base)


class TestBundleManagerBootstrap:
    """Tests for BundleManager bootstrap functionality."""

    @pytest.fixture
    def paths(self, tmp_path: Path) -> LucidscanPaths:
        home = tmp_path / ".lucidscan"
        return LucidscanPaths(home)

    @pytest.fixture
    def platform_info(self) -> PlatformInfo:
        return PlatformInfo(os="linux", arch="amd64")

    @pytest.fixture
    def manager(self, paths: LucidscanPaths, platform_info: PlatformInfo) -> BundleManager:
        return BundleManager(paths=paths, platform_info=platform_info)

    def test_bootstrap_creates_directories(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        # Mock the download and extract methods since we can't actually download
        with patch.object(manager, "_download_bundle") as mock_download:
            with patch.object(manager, "_extract_bundle") as mock_extract:
                mock_download.return_value = Path("/tmp/bundle.tar.gz")
                mock_extract.return_value = None

                manager.bootstrap()

                assert paths.home.exists()
                assert paths.bin_dir.exists()
                assert paths.config_dir.exists()

    def test_bootstrap_writes_versions_on_success(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        with patch.object(manager, "_download_bundle") as mock_download:
            with patch.object(manager, "_extract_bundle") as mock_extract:
                mock_download.return_value = Path("/tmp/bundle.tar.gz")
                mock_extract.return_value = None

                manager.bootstrap()

                assert paths.versions_json.exists()

    def test_bootstrap_force_redownloads(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        # First bootstrap
        paths.ensure_directories()
        paths.versions_json.write_text('{"lucidscan": "0.1.0"}')

        with patch.object(manager, "_download_bundle") as mock_download:
            with patch.object(manager, "_extract_bundle") as mock_extract:
                mock_download.return_value = Path("/tmp/bundle.tar.gz")
                mock_extract.return_value = None

                # Force should still run even though initialized
                manager.bootstrap(force=True)

                mock_download.assert_called_once()

    def test_bootstrap_skips_if_already_initialized(
        self, manager: BundleManager, paths: LucidscanPaths
    ) -> None:
        paths.ensure_directories()
        paths.versions_json.write_text('{"lucidscan": "0.1.0"}')

        with patch.object(manager, "_download_bundle") as mock_download:
            # Without force, should skip
            manager.bootstrap(force=False)
            mock_download.assert_not_called()

