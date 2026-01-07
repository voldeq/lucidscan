"""List scanners command implementation."""

from __future__ import annotations

from argparse import Namespace

from lucidscan.cli.commands import Command
from lucidscan.cli.exit_codes import EXIT_SUCCESS
from lucidscan.plugins.scanners import discover_scanner_plugins


class ListScannersCommand(Command):
    """Lists all available scanner plugins."""

    @property
    def name(self) -> str:
        """Command identifier."""
        return "list_scanners"

    def execute(self, args: Namespace) -> int:
        """Execute the list-scanners command.

        Displays all available scanner plugins with their domains and versions.

        Args:
            args: Parsed command-line arguments.

        Returns:
            Exit code (always 0 for list-scanners).
        """
        plugins = discover_scanner_plugins()

        print("Available scanner plugins:")
        print()

        if plugins:
            for name, plugin_class in sorted(plugins.items()):
                try:
                    plugin = plugin_class()
                    domains = ", ".join(d.value.upper() for d in plugin.domains)
                    version_str = plugin.get_version()
                    print(f"  {name}")
                    print(f"    Domains: {domains}")
                    print(f"    Version: {version_str}")
                    print()
                except Exception as e:
                    print(f"  {name}: error loading plugin ({e})")
                    print()
        else:
            print("  No plugins discovered.")
            print()
            print("Install plugins via pip, e.g.: pip install lucidscan-snyk")

        return EXIT_SUCCESS
