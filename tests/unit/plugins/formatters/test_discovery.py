"""Unit tests for formatter plugin discovery."""

from __future__ import annotations

from lucidshark.plugins.formatters import discover_formatter_plugins
from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.discovery import get_all_available_tools


class TestFormatterDiscovery:
    def test_discover_formatter_plugins(self) -> None:
        """Test that all formatter plugins are discovered."""
        plugins = discover_formatter_plugins()
        assert "ruff_format" in plugins
        assert "prettier" in plugins
        assert "rustfmt" in plugins
        assert "google_java_format" in plugins

    def test_discovered_plugins_inherit_from_base(self) -> None:
        """Test that all discovered plugins inherit from FormatterPlugin."""
        plugins = discover_formatter_plugins()
        for name, plugin_class in plugins.items():
            assert issubclass(plugin_class, FormatterPlugin), (
                f"Plugin {name} does not inherit from FormatterPlugin"
            )

    def test_discovered_plugins_are_instantiable(self) -> None:
        """Test that all discovered plugins can be instantiated without error."""
        plugins = discover_formatter_plugins()
        for name, plugin_class in plugins.items():
            instance = plugin_class()
            assert instance is not None, f"Plugin {name} returned None on instantiation"

    def test_discovered_plugin_count(self) -> None:
        """Test that at least 4 formatter plugins are discovered."""
        plugins = discover_formatter_plugins()
        assert len(plugins) >= 4, (
            f"Expected at least 4 formatter plugins, got {len(plugins)}: {list(plugins.keys())}"
        )

    def test_get_all_available_tools_includes_formatters(self) -> None:
        """Test that get_all_available_tools includes formatters."""
        tools = get_all_available_tools()
        assert "formatters" in tools
        assert "ruff_format" in tools["formatters"]
