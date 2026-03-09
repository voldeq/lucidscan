"""Help command implementation."""

from __future__ import annotations

from argparse import Namespace
from importlib.resources import files  # nosemgrep: python37-compatibility-importlib2
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lucidshark.config.models import LucidSharkConfig

from lucidshark.cli.commands import Command
from lucidshark.cli.exit_codes import EXIT_SUCCESS


def get_help_content() -> str:
    """Load help documentation from package resources.

    Returns:
        Help documentation as markdown string.
    """
    # Try to load from bundled package data (works for pip install and PyInstaller)
    try:
        data_dir = files("lucidshark").joinpath("data/help.md")
        return data_dir.read_text(encoding="utf-8")
    except (FileNotFoundError, TypeError):
        pass

    # Fall back to docs/ in project root (development without install)
    from pathlib import Path

    docs_path = Path(__file__).parent.parent.parent.parent.parent / "docs" / "help.md"
    if docs_path.exists():
        return docs_path.read_text(encoding="utf-8")

    return (
        "Help documentation not found. Visit https://github.com/toniantunovi/lucidshark"
    )


class HelpCommand(Command):
    """Shows LucidShark documentation."""

    def __init__(self, version: str):
        """Initialize HelpCommand.

        Args:
            version: Current lucidshark version string.
        """
        self._version = version

    @property
    def name(self) -> str:
        """Command identifier."""
        return "help"

    def execute(self, args: Namespace, config: "LucidSharkConfig | None" = None) -> int:
        """Execute the help command.

        Displays LucidShark documentation.

        Args:
            args: Parsed command-line arguments.
            config: Optional LucidShark configuration (unused).

        Returns:
            Exit code (always 0 for help).
        """
        content = get_help_content()
        print(content)
        return EXIT_SUCCESS
