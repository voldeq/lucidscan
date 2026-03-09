"""Formatter plugins for lucidshark.

This module provides formatter integrations for the quality pipeline.
Formatters are discovered via the lucidshark.formatters entry point group.
"""

from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.discovery import (
    discover_plugins,
    FORMATTER_ENTRY_POINT_GROUP,
)


def discover_formatter_plugins():
    """Discover all installed formatter plugins.

    Returns:
        Dictionary mapping plugin names to plugin classes.
    """
    return discover_plugins(FORMATTER_ENTRY_POINT_GROUP, FormatterPlugin)


__all__ = [
    "FormatterPlugin",
    "discover_formatter_plugins",
]
