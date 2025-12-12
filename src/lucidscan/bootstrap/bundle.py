"""Bundle management for lucidscan tools.

Handles downloading, extracting, and managing scanner tool bundles.
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from lucidscan import __version__ as LUCIDSCAN_VERSION
from lucidscan.bootstrap.paths import LucidscanPaths
from lucidscan.bootstrap.platform import PlatformInfo
from lucidscan.core.logging import get_logger

LOGGER = get_logger(__name__)

# Default base URL for bundle downloads
DEFAULT_BUNDLE_BASE_URL = "https://downloads.lucidscan.io/tools"

# Expected scanner versions for this release (updated when lucidscan is released)
EXPECTED_VERSIONS = {
    "trivy": "0.52.0",
    "semgrep": "1.80.0",
    "checkov": "3.2.12",
}


class BundleError(Exception):
    """Error related to bundle operations."""

    pass


@dataclass
class BundleVersions:
    """Version information for bundled tools.

    Stored in ~/.lucidscan/config/versions.json
    """

    lucidscan: str = ""
    trivy: str = ""
    semgrep: str = ""
    checkov: str = ""
    bundle_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "lucidscan": self.lucidscan,
            "trivy": self.trivy,
            "semgrep": self.semgrep,
            "checkov": self.checkov,
            "bundleVersion": self.bundle_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BundleVersions":
        """Create from dictionary (e.g., from JSON)."""
        return cls(
            lucidscan=data.get("lucidscan", ""),
            trivy=data.get("trivy", ""),
            semgrep=data.get("semgrep", ""),
            checkov=data.get("checkov", ""),
            bundle_version=data.get("bundleVersion", ""),
        )


def construct_bundle_url(
    platform_info: PlatformInfo, base_url: str = DEFAULT_BUNDLE_BASE_URL
) -> str:
    """Construct the download URL for a platform-specific bundle.

    Args:
        platform_info: Platform information (OS and architecture).
        base_url: Base URL for bundle downloads.

    Returns:
        Full URL to the bundle archive.
    """
    extension = ".zip" if platform_info.os == "windows" else ".tar.gz"
    bundle_name = f"lucidscan-tools-{platform_info.bundle_name}{extension}"
    return f"{base_url}/{bundle_name}"


@dataclass
class BundleManager:
    """Manages the lucidscan tool bundle lifecycle.

    Handles:
    - First-run detection
    - Bundle download and extraction
    - Version tracking
    - Update management
    """

    paths: LucidscanPaths
    platform_info: PlatformInfo
    bundle_base_url: str = DEFAULT_BUNDLE_BASE_URL

    def needs_bootstrap(self) -> bool:
        """Check if bootstrap is needed.

        Returns True if the tool bundle has not been initialized.
        """
        return not self.paths.is_initialized()

    def read_versions(self) -> Optional[BundleVersions]:
        """Read versions.json if it exists.

        Returns:
            BundleVersions if file exists, None otherwise.
        """
        if not self.paths.versions_json.exists():
            return None
        try:
            data = json.loads(self.paths.versions_json.read_text())
            return BundleVersions.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            LOGGER.warning(f"Failed to parse versions.json: {e}")
            return None

    def write_versions(self, versions: BundleVersions) -> None:
        """Write versions.json.

        Args:
            versions: Version information to write.
        """
        self.paths.versions_json.write_text(
            json.dumps(versions.to_dict(), indent=2) + "\n"
        )

    def get_bundle_url(self) -> str:
        """Get the bundle download URL for the current platform."""
        return construct_bundle_url(self.platform_info, self.bundle_base_url)

    def bootstrap(self, force: bool = False) -> None:
        """Initialize the tool bundle.

        Downloads and extracts scanner tools to ~/.lucidscan if not already
        initialized, or if force is True.

        Args:
            force: If True, re-download even if already initialized.

        Raises:
            BundleError: If download or extraction fails.
        """
        if not force and not self.needs_bootstrap():
            LOGGER.info("Tool bundle already initialized, skipping bootstrap.")
            return

        LOGGER.info("Initializing lucidscan tool bundle...")

        # Ensure directory structure exists
        self.paths.ensure_directories()

        try:
            # Download the bundle
            bundle_path = self._download_bundle()

            # Extract the bundle
            self._extract_bundle(bundle_path)

            # Write versions.json
            versions = BundleVersions(
                lucidscan=LUCIDSCAN_VERSION,
                trivy=EXPECTED_VERSIONS["trivy"],
                semgrep=EXPECTED_VERSIONS["semgrep"],
                checkov=EXPECTED_VERSIONS["checkov"],
                bundle_version=self._get_bundle_version(),
            )
            self.write_versions(versions)

            LOGGER.info("Tool bundle initialized successfully.")

        except Exception as e:
            LOGGER.error(f"Bootstrap failed: {e}")
            raise BundleError(f"Failed to initialize tool bundle: {e}") from e

    def _get_bundle_version(self) -> str:
        """Generate a bundle version string based on current date."""
        from datetime import datetime

        return datetime.now().strftime("%Y.%m.%d")

    def _download_bundle(self) -> Path:
        """Download the tool bundle.

        Returns:
            Path to the downloaded archive.

        Raises:
            BundleError: If download fails.
        """
        url = self.get_bundle_url()
        LOGGER.info(f"Downloading tool bundle from {url}")

        try:
            # Create a temporary file for the download
            extension = ".zip" if self.platform_info.os == "windows" else ".tar.gz"
            fd, temp_path = tempfile.mkstemp(suffix=extension)
            os.close(fd)
            temp_path = Path(temp_path)

            # Download with progress indication
            request = Request(url, headers={"User-Agent": f"lucidscan/{LUCIDSCAN_VERSION}"})

            try:
                with urlopen(request, timeout=300) as response:
                    total_size = response.getheader("Content-Length")
                    if total_size:
                        LOGGER.info(f"Bundle size: {int(total_size) / 1024 / 1024:.1f} MB")

                    with open(temp_path, "wb") as f:
                        shutil.copyfileobj(response, f)

            except HTTPError as e:
                raise BundleError(
                    f"Failed to download bundle: HTTP {e.code} - {e.reason}"
                ) from e
            except URLError as e:
                raise BundleError(
                    f"Failed to download bundle: {e.reason}. "
                    "Check your network connection."
                ) from e

            LOGGER.info("Bundle downloaded successfully.")
            return temp_path

        except Exception as e:
            if isinstance(e, BundleError):
                raise
            raise BundleError(f"Unexpected error during download: {e}") from e

    def _extract_bundle(self, bundle_path: Path) -> None:
        """Extract the downloaded bundle to ~/.lucidscan.

        Args:
            bundle_path: Path to the downloaded archive.

        Raises:
            BundleError: If extraction fails.
        """
        LOGGER.info(f"Extracting bundle to {self.paths.home}")

        try:
            if bundle_path.suffix == ".zip" or bundle_path.name.endswith(".zip"):
                self._extract_zip(bundle_path)
            else:
                self._extract_tarball(bundle_path)

            # Make binaries executable
            self._set_executable_permissions()

            LOGGER.info("Bundle extracted successfully.")

        except Exception as e:
            raise BundleError(f"Failed to extract bundle: {e}") from e
        finally:
            # Clean up temporary file
            try:
                bundle_path.unlink()
            except OSError:
                pass

    def _extract_tarball(self, archive_path: Path) -> None:
        """Extract a .tar.gz archive."""
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise BundleError(
                        f"Unsafe path in archive: {member.name}"
                    )
            tar.extractall(path=self.paths.home)

    def _extract_zip(self, archive_path: Path) -> None:
        """Extract a .zip archive."""
        with zipfile.ZipFile(archive_path, "r") as zf:
            # Security: check for path traversal
            for name in zf.namelist():
                if name.startswith("/") or ".." in name:
                    raise BundleError(f"Unsafe path in archive: {name}")
            zf.extractall(path=self.paths.home)

    def _set_executable_permissions(self) -> None:
        """Set executable permissions on binaries."""
        binaries = [
            self.paths.trivy_bin,
            self.paths.semgrep_bin,
            self.paths.checkov_bin,
        ]
        for binary in binaries:
            if binary.exists():
                binary.chmod(binary.stat().st_mode | 0o111)

    def update_tools(self) -> None:
        """Update the tool bundle to the latest version.

        Equivalent to bootstrap with force=True.
        """
        self.bootstrap(force=True)

