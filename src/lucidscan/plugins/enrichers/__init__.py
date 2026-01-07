"""Enricher plugins for lucidscan post-processing.

Enricher plugins process scan results after scanner execution,
adding context, metadata, or performing transformations like
deduplication or AI-powered explanations.

Plugins are discovered via Python entry points (lucidscan.enrichers group).

Example registration in pyproject.toml:
    [project.entry-points."lucidscan.enrichers"]
    dedup = "lucidscan_dedup:DedupEnricher"
    epss = "lucidscan_epss:EPSSEnricher"
"""

from typing import Dict, List, Optional, Type

from lucidscan.plugins.enrichers.base import EnricherPlugin
from lucidscan.plugins.discovery import (
    ENRICHER_ENTRY_POINT_GROUP,
    discover_plugins,
    get_plugin,
    list_available_plugins as _list_plugins,
)


def discover_enricher_plugins() -> Dict[str, Type[EnricherPlugin]]:
    """Discover all installed enricher plugins via entry points.

    Returns:
        Dictionary mapping plugin names to plugin classes.
    """
    return discover_plugins(ENRICHER_ENTRY_POINT_GROUP, EnricherPlugin)


def get_enricher_plugin(name: str) -> Optional[EnricherPlugin]:
    """Get an instantiated enricher plugin by name.

    Args:
        name: Plugin name (e.g., 'dedup', 'epss').

    Returns:
        Instantiated EnricherPlugin or None if not found.
    """
    return get_plugin(ENRICHER_ENTRY_POINT_GROUP, name, EnricherPlugin)


def list_available_enrichers() -> List[str]:
    """List names of all available enricher plugins.

    Returns:
        List of enricher plugin names.
    """
    return _list_plugins(ENRICHER_ENTRY_POINT_GROUP)


__all__ = [
    "EnricherPlugin",
    "discover_enricher_plugins",
    "get_enricher_plugin",
    "list_available_enrichers",
]
