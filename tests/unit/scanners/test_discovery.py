"""Tests for scanner plugin discovery functionality."""

from __future__ import annotations

from lucidscan.plugins.scanners import (
    discover_scanner_plugins,
    get_scanner_plugin,
    list_available_scanners,
    ScannerPlugin,
    TrivyScanner,
)


class TestDiscoverScannerPlugins:
    """Tests for discover_scanner_plugins function."""

    def test_discovers_trivy_plugin(self) -> None:
        """Test that Trivy plugin is discovered via entry points."""
        plugins = discover_scanner_plugins()
        assert "trivy" in plugins
        assert plugins["trivy"] is TrivyScanner

    def test_returns_dict_of_plugin_classes(self) -> None:
        """Test that discovered plugins are ScannerPlugin subclasses."""
        plugins = discover_scanner_plugins()
        for name, plugin_class in plugins.items():
            assert issubclass(plugin_class, ScannerPlugin)


class TestGetScannerPlugin:
    """Tests for get_scanner_plugin function."""

    def test_returns_trivy_instance(self) -> None:
        """Test getting an instantiated Trivy plugin."""
        plugin = get_scanner_plugin("trivy")
        assert plugin is not None
        assert isinstance(plugin, TrivyScanner)
        assert plugin.name == "trivy"

    def test_returns_none_for_unknown_plugin(self) -> None:
        """Test that unknown plugin names return None."""
        plugin = get_scanner_plugin("nonexistent")
        assert plugin is None


class TestListAvailableScanners:
    """Tests for list_available_scanners function."""

    def test_lists_trivy(self) -> None:
        """Test that trivy is in the list of available scanners."""
        scanners = list_available_scanners()
        assert "trivy" in scanners

    def test_returns_list_of_strings(self) -> None:
        """Test that the function returns a list of scanner names."""
        scanners = list_available_scanners()
        assert isinstance(scanners, list)
        for name in scanners:
            assert isinstance(name, str)
