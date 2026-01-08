"""Coverage plugins for lucidscan.

This module provides coverage analysis integrations for the quality pipeline.
Coverage plugins are discovered via the lucidscan.coverage entry point group.
"""

from lucidscan.plugins.coverage.base import CoveragePlugin, CoverageResult, FileCoverage
from lucidscan.plugins.discovery import (
    discover_plugins,
    COVERAGE_ENTRY_POINT_GROUP,
)


def discover_coverage_plugins():
    """Discover all installed coverage plugins.

    Returns:
        Dictionary mapping plugin names to plugin classes.
    """
    return discover_plugins(COVERAGE_ENTRY_POINT_GROUP, CoveragePlugin)


__all__ = [
    "CoveragePlugin",
    "CoverageResult",
    "FileCoverage",
    "discover_coverage_plugins",
]
