"""Path management for lucidscan plugin binary cache.

Handles the .lucidscan directory structure and path resolution.
Each scanner plugin manages its own binary under .lucidscan/bin/{tool}/{version}/.

By default, tools are stored in the project root under .lucidscan/.
The LUCIDSCAN_HOME environment variable can override this for global installations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Optional

# Default directory name
DEFAULT_HOME_DIR_NAME = ".lucidscan"

# Environment variable to override home directory (for global installations)
LUCIDSCAN_HOME_ENV = "LUCIDSCAN_HOME"


def get_lucidscan_home(project_root: Optional[Path] = None) -> Path:
    """Get the lucidscan home directory path.

    Resolution order:
    1. LUCIDSCAN_HOME environment variable (if set) - for global installations
    2. {project_root}/.lucidscan (if project_root provided)
    3. {cwd}/.lucidscan (default)

    Args:
        project_root: Optional project root directory. If not provided,
                     uses current working directory.

    Returns:
        Path to the lucidscan home directory.
    """
    # Global override takes precedence
    env_home = os.environ.get(LUCIDSCAN_HOME_ENV)
    if env_home:
        return Path(env_home)

    # Use project root or current directory
    if project_root:
        return project_root / DEFAULT_HOME_DIR_NAME

    return Path.cwd() / DEFAULT_HOME_DIR_NAME


@dataclass
class LucidscanPaths:
    """Manages paths within the lucidscan home directory.

    Directory structure (plugin-based):
        {project}/.lucidscan/
            bin/
                trivy/{version}/trivy       - Trivy binary
                opengrep/{version}/opengrep - OpenGrep binary
                checkov/{version}/venv/     - Checkov virtualenv
                ruff/{version}/ruff         - Ruff binary
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
        """Create paths from the default lucidscan home (cwd/.lucidscan)."""
        return cls(get_lucidscan_home())

    @classmethod
    def for_project(cls, project_root: Path) -> "LucidscanPaths":
        """Create paths for a specific project.

        Args:
            project_root: Project root directory.

        Returns:
            LucidscanPaths configured for the project.
        """
        return cls(get_lucidscan_home(project_root))

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
            plugin_name: Name of the plugin (e.g., 'trivy', 'opengrep').
            version: Version string.

        Returns:
            Path to the plugin's version-specific binary directory.
        """
        return self.bin_dir / plugin_name / version

    def plugin_cache_dir(self, plugin_name: str) -> Path:
        """Get the cache directory for a specific plugin.

        Args:
            plugin_name: Name of the plugin.

        Returns:
            Path to the plugin's cache directory.
        """
        return self.cache_dir / plugin_name

    def ensure_directories(self) -> None:
        """Create all required directories if they don't exist."""
        directories = [
            self.home,
            self.bin_dir,
            self.cache_dir,
            self.config_dir,
            self.logs_dir,
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
