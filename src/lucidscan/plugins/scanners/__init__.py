"""Scanner plugins for integrating external security tools.

Plugins are discovered via Python entry points (lucidscan.scanners group).
"""

from pathlib import Path
from typing import Dict, Optional, Type

from lucidscan.plugins.scanners.base import ScannerPlugin
from lucidscan.plugins.scanners.trivy import TrivyScanner
from lucidscan.plugins.scanners.opengrep import OpenGrepScanner
from lucidscan.plugins.scanners.checkov import CheckovScanner
from lucidscan.plugins import SCANNER_ENTRY_POINT_GROUP
from lucidscan.plugins.discovery import discover_plugins, get_plugin, list_available_plugins as _list_plugins


def discover_scanner_plugins() -> Dict[str, Type[ScannerPlugin]]:
    """Discover all installed scanner plugins via entry points."""
    return discover_plugins(SCANNER_ENTRY_POINT_GROUP, ScannerPlugin)


def get_scanner_plugin(
    name: str,
    project_root: Optional[Path] = None,
) -> ScannerPlugin | None:
    """Get an instantiated scanner plugin by name.

    Args:
        name: Scanner plugin name (e.g., 'trivy').
        project_root: Optional project root for tool installation.
                     If provided, tools are installed to {project_root}/.lucidscan/

    Returns:
        Instantiated scanner plugin or None if not found.
    """
    kwargs = {}
    if project_root:
        kwargs["project_root"] = project_root
    return get_plugin(SCANNER_ENTRY_POINT_GROUP, name, ScannerPlugin, **kwargs)


def list_available_scanners() -> list[str]:
    """List names of all available scanner plugins."""
    return _list_plugins(SCANNER_ENTRY_POINT_GROUP)


__all__ = [
    "ScannerPlugin",
    "TrivyScanner",
    "OpenGrepScanner",
    "CheckovScanner",
    "discover_scanner_plugins",
    "get_scanner_plugin",
    "list_available_scanners",
]


