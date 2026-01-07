"""Tests for generic plugin discovery infrastructure."""

from __future__ import annotations

from lucidscan.plugins import (
    discover_plugins,
    get_plugin,
    list_available_plugins,
    SCANNER_ENTRY_POINT_GROUP,
)
from lucidscan.plugins.scanners.base import ScannerPlugin
from lucidscan.plugins.scanners.trivy import TrivyScanner


class TestDiscoverPlugins:
    """Tests for generic discover_plugins function."""

    def test_discovers_scanner_plugins(self) -> None:
        """Test discovering plugins from scanner entry point group."""
        plugins = discover_plugins(SCANNER_ENTRY_POINT_GROUP)
        assert "trivy" in plugins

    def test_validates_base_class(self) -> None:
        """Test that base_class validation filters plugins."""
        plugins = discover_plugins(SCANNER_ENTRY_POINT_GROUP, ScannerPlugin)
        for plugin_class in plugins.values():
            assert issubclass(plugin_class, ScannerPlugin)

    def test_returns_empty_dict_for_unknown_group(self) -> None:
        """Test that unknown group returns empty dict."""
        plugins = discover_plugins("lucidscan.nonexistent")
        assert plugins == {}


class TestGetPlugin:
    """Tests for generic get_plugin function."""

    def test_gets_trivy_from_scanner_group(self) -> None:
        """Test getting Trivy plugin from scanner group."""
        plugin = get_plugin(SCANNER_ENTRY_POINT_GROUP, "trivy", ScannerPlugin)
        assert plugin is not None
        assert isinstance(plugin, TrivyScanner)

    def test_returns_none_for_unknown_plugin(self) -> None:
        """Test that unknown plugin returns None."""
        plugin = get_plugin(SCANNER_ENTRY_POINT_GROUP, "unknown")
        assert plugin is None


class TestListAvailablePlugins:
    """Tests for generic list_available_plugins function."""

    def test_lists_scanner_plugins(self) -> None:
        """Test listing plugins from scanner group."""
        plugins = list_available_plugins(SCANNER_ENTRY_POINT_GROUP)
        assert "trivy" in plugins

    def test_returns_empty_list_for_unknown_group(self) -> None:
        """Test that unknown group returns empty list."""
        plugins = list_available_plugins("lucidscan.nonexistent")
        assert plugins == []
