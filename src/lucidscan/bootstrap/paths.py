"""Path management for lucidscan plugin binary cache.

Handles the ~/.lucidscan directory structure and path resolution.
Each scanner plugin manages its own binary under ~/.lucidscan/bin/{tool}/{version}/.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

# Default directory name under user home
DEFAULT_HOME_DIR_NAME = ".lucidscan"

# Environment variable to override home directory
LUCIDSCAN_HOME_ENV = "LUCIDSCAN_HOME"


def get_lucidscan_home() -> Path:
    """Get the lucidscan home directory path.

    Resolution order:
    1. LUCIDSCAN_HOME environment variable (if set)
    2. ~/.lucidscan (default)

    Returns:
        Path to the lucidscan home directory.
    """
    env_home = os.environ.get(LUCIDSCAN_HOME_ENV)
    if env_home:
        return Path(env_home)
    return Path.home() / DEFAULT_HOME_DIR_NAME


@dataclass
class LucidscanPaths:
    """Manages paths within the lucidscan home directory.

    Directory structure (plugin-based):
        ~/.lucidscan/
            bin/
                trivy/{version}/trivy       - Trivy binary
                opengrep/{version}/opengrep - OpenGrep binary
                checkov/{version}/venv/     - Checkov virtualenv
            cache/
                trivy/                      - Trivy vulnerability DB
            config/                         - Configuration files
            logs/                           - Debug/diagnostic logs
    """

    home: Path

    # Subdirectory names
    _BIN_DIR: ClassVar[str] = "bin"
    _CACHE_DIR: ClassVar[str] = "cache"
    _CONFIG_DIR: ClassVar[str] = "config"
    _LOGS_DIR: ClassVar[str] = "logs"

    @classmethod
    def default(cls) -> "LucidscanPaths":
        """Create paths from the default lucidscan home."""
        return cls(get_lucidscan_home())

    @property
    def bin_dir(self) -> Path:
        """Directory containing scanner plugin binaries."""
        return self.home / self._BIN_DIR

    @property
    def cache_dir(self) -> Path:
        """Directory for scanner caches."""
        return self.home / self._CACHE_DIR

    @property
    def config_dir(self) -> Path:
        """Directory for configuration files."""
        return self.home / self._CONFIG_DIR

    @property
    def logs_dir(self) -> Path:
        """Directory for log files."""
        return self.home / self._LOGS_DIR

    def plugin_bin_dir(self, plugin_name: str, version: str) -> Path:
        """Get the binary directory for a specific plugin version.

        Args:
            plugin_name: Name of the plugin (trivy, opengrep, checkov).
            version: Version string.

        Returns:
            Path to the plugin's version-specific binary directory.
        """
        return self.bin_dir / plugin_name / version

    @property
    def trivy_bin(self) -> Path:
        """Path to the trivy binary (uses 'current' symlink or first available version)."""
        trivy_dir = self.bin_dir / "trivy"
        current_link = trivy_dir / "current"
        if current_link.exists():
            return current_link / "trivy"
        # Fallback: find any version directory
        if trivy_dir.exists():
            for version_dir in trivy_dir.iterdir():
                if version_dir.is_dir() and version_dir.name != "current":
                    return version_dir / "trivy"
        return trivy_dir / "trivy"  # Fallback path

    @property
    def opengrep_bin(self) -> Path:
        """Path to the opengrep binary (uses 'current' symlink or first available version)."""
        opengrep_dir = self.bin_dir / "opengrep"
        current_link = opengrep_dir / "current"
        if current_link.exists():
            return current_link / "opengrep"
        # Fallback: find any version directory
        if opengrep_dir.exists():
            for version_dir in opengrep_dir.iterdir():
                if version_dir.is_dir() and version_dir.name != "current":
                    return version_dir / "opengrep"
        return opengrep_dir / "opengrep"  # Fallback path

    @property
    def checkov_bin(self) -> Path:
        """Path to the checkov binary in its virtualenv."""
        checkov_dir = self.bin_dir / "checkov"
        current_link = checkov_dir / "current"
        if current_link.exists():
            return current_link / "venv" / "bin" / "checkov"
        # Fallback: find any version directory
        if checkov_dir.exists():
            for version_dir in checkov_dir.iterdir():
                if version_dir.is_dir() and version_dir.name != "current":
                    return version_dir / "venv" / "bin" / "checkov"
        return checkov_dir / "venv" / "bin" / "checkov"  # Fallback path

    @property
    def trivy_cache(self) -> Path:
        """Path to Trivy cache directory."""
        return self.cache_dir / "trivy"

    def ensure_directories(self) -> None:
        """Create all required directories if they don't exist."""
        directories = [
            self.home,
            self.bin_dir,
            self.cache_dir,
            self.config_dir,
            self.logs_dir,
            self.trivy_cache,
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def is_initialized(self) -> bool:
        """Check if any scanner plugins have been installed.

        Returns True if the bin directory exists and contains at least
        one plugin subdirectory.
        """
        if not self.bin_dir.exists():
            return False
        # Check if any plugin directories exist
        for plugin_dir in self.bin_dir.iterdir():
            if plugin_dir.is_dir():
                return True
        return False
