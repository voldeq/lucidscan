"""Path management for lucidscan tool bundle.

Handles the ~/.lucidscan directory structure and path resolution.
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

    Directory structure:
        ~/.lucidscan/
            bin/           - Scanner binaries (trivy, semgrep)
            checkov-env/   - Checkov virtualenv
            cache/         - Scanner caches (trivy DB, etc.)
            config/        - Configuration files, versions.json
            logs/          - Debug/diagnostic logs
    """

    home: Path

    # Subdirectory names
    _BIN_DIR: ClassVar[str] = "bin"
    _CHECKOV_ENV_DIR: ClassVar[str] = "checkov-env"
    _CACHE_DIR: ClassVar[str] = "cache"
    _CONFIG_DIR: ClassVar[str] = "config"
    _LOGS_DIR: ClassVar[str] = "logs"

    @classmethod
    def default(cls) -> "LucidscanPaths":
        """Create paths from the default lucidscan home."""
        return cls(get_lucidscan_home())

    @property
    def bin_dir(self) -> Path:
        """Directory containing scanner binaries."""
        return self.home / self._BIN_DIR

    @property
    def checkov_env(self) -> Path:
        """Directory containing Checkov virtualenv."""
        return self.home / self._CHECKOV_ENV_DIR

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

    @property
    def trivy_bin(self) -> Path:
        """Path to the trivy binary."""
        return self.bin_dir / "trivy"

    @property
    def semgrep_bin(self) -> Path:
        """Path to the semgrep binary."""
        return self.bin_dir / "semgrep"

    @property
    def checkov_bin(self) -> Path:
        """Path to the checkov binary in its virtualenv."""
        return self.checkov_env / "bin" / "checkov"

    @property
    def versions_json(self) -> Path:
        """Path to versions.json file."""
        return self.config_dir / "versions.json"

    @property
    def trivy_cache(self) -> Path:
        """Path to Trivy cache directory."""
        return self.cache_dir / "trivy"

    def ensure_directories(self) -> None:
        """Create all required directories if they don't exist."""
        directories = [
            self.home,
            self.bin_dir,
            self.checkov_env,
            self.cache_dir,
            self.config_dir,
            self.logs_dir,
            self.trivy_cache,
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def is_initialized(self) -> bool:
        """Check if lucidscan has been initialized.

        Returns True if versions.json exists, indicating a successful
        bootstrap has been performed.
        """
        return self.versions_json.exists()

