"""Serve command implementation.

Run LucidShark as an MCP server for AI agents or as a file watcher.
"""

from __future__ import annotations

import asyncio
from argparse import Namespace
from pathlib import Path

from lucidshark.cli.commands import Command
from lucidshark.cli.exit_codes import EXIT_SUCCESS, EXIT_SCANNER_ERROR
from lucidshark.config import LucidSharkConfig
from lucidshark.core.logging import get_logger

LOGGER = get_logger(__name__)


class ServeCommand(Command):
    """Run LucidShark as a server for AI integration."""

    def __init__(self, version: str):
        """Initialize ServeCommand.

        Args:
            version: Current lucidshark version string.
        """
        self._version = version

    @property
    def name(self) -> str:
        """Command identifier."""
        return "serve"

    def execute(self, args: Namespace, config: "LucidSharkConfig | None" = None) -> int:
        """Execute the serve command.

        Args:
            args: Parsed command-line arguments.
            config: LucidShark configuration.

        Returns:
            Exit code.
        """
        if config is None:
            LOGGER.error("Configuration is required for serve command")
            return EXIT_SCANNER_ERROR

        project_root = Path(args.path).resolve()

        if not project_root.is_dir():
            LOGGER.error(f"Not a directory: {project_root}")
            return EXIT_SCANNER_ERROR

        # Determine mode
        if args.mcp:
            return self._run_mcp_server(args, config, project_root)
        elif args.watch:
            return self._run_file_watcher(args, config, project_root)
        else:
            # Default to MCP mode
            return self._run_mcp_server(args, config, project_root)

    def _run_mcp_server(
        self,
        args: Namespace,
        config: LucidSharkConfig,
        project_root: Path,
    ) -> int:
        """Run LucidShark as an MCP server.

        Args:
            args: Parsed command-line arguments.
            config: LucidShark configuration.
            project_root: Project root directory.

        Returns:
            Exit code.
        """
        try:
            from lucidshark.mcp.server import LucidSharkMCPServer

            LOGGER.info(f"Starting MCP server for {project_root}")
            server = LucidSharkMCPServer(project_root, config)
            asyncio.run(server.run())
            return EXIT_SUCCESS
        except ImportError as e:
            LOGGER.error(f"MCP import error: {e}")
            return EXIT_SCANNER_ERROR
        except Exception as e:
            LOGGER.error(f"MCP server error: {e}")
            return EXIT_SCANNER_ERROR

    def _run_file_watcher(
        self,
        args: Namespace,
        config: LucidSharkConfig,
        project_root: Path,
    ) -> int:
        """Run LucidShark in file watcher mode.

        Args:
            args: Parsed command-line arguments.
            config: LucidShark configuration.
            project_root: Project root directory.

        Returns:
            Exit code.
        """
        try:
            from lucidshark.mcp.watcher import LucidSharkFileWatcher

            debounce_ms = getattr(args, "debounce", 1000)
            LOGGER.info(f"Starting file watcher for {project_root}")
            LOGGER.info(f"Debounce: {debounce_ms}ms")

            watcher = LucidSharkFileWatcher(
                project_root=project_root,
                config=config,
                debounce_ms=debounce_ms,
            )

            # Set up result callback
            def on_result(result):
                """Print scan results to stdout."""
                import json

                print(json.dumps(result, indent=2))

            watcher.on_result(on_result)
            asyncio.run(watcher.start())
            return EXIT_SUCCESS
        except ImportError as e:
            LOGGER.error(f"Watcher dependencies not installed: {e}")
            return EXIT_SCANNER_ERROR
        except KeyboardInterrupt:
            LOGGER.info("File watcher stopped")
            return EXIT_SUCCESS
        except Exception as e:
            LOGGER.error(f"File watcher error: {e}")
            return EXIT_SCANNER_ERROR
