from __future__ import annotations

import argparse
import sys
from typing import Iterable, Optional

from importlib.metadata import version, PackageNotFoundError

from lucidscan.core.logging import configure_logging, get_logger
from lucidscan.bootstrap.paths import get_lucidscan_home, LucidscanPaths
from lucidscan.bootstrap.platform import get_platform_info
from lucidscan.bootstrap.validation import validate_tools, ToolStatus


LOGGER = get_logger(__name__)

# Exit codes per Section 14 of the spec
EXIT_SUCCESS = 0
EXIT_ISSUES_FOUND = 1
EXIT_SCANNER_ERROR = 2
EXIT_INVALID_USAGE = 3
EXIT_BOOTSTRAP_FAILURE = 4


def _get_version() -> str:
    try:
        return version("lucidscan")
    except PackageNotFoundError:
        # Fallback for editable installs that have not yet built metadata.
        from lucidscan import __version__

        return __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lucidscan",
        description="lucidscan — Plugin-based security scanning framework.",
    )

    # Global options
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show lucidscan version and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose (info-level) logging.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce logging output to errors only.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "table", "sarif", "summary"],
        default="json",
        help="Output format (default: json).",
    )

    # Status flag
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show scanner plugin status and installed versions.",
    )

    # Scanner domain flags
    parser.add_argument(
        "--sca",
        action="store_true",
        help="Enable Software Composition Analysis (Trivy plugin).",
    )
    parser.add_argument(
        "--container",
        action="store_true",
        help="Enable container image scanning (Trivy plugin).",
    )
    parser.add_argument(
        "--iac",
        action="store_true",
        help="Enable Infrastructure-as-Code scanning (Checkov plugin).",
    )
    parser.add_argument(
        "--sast",
        action="store_true",
        help="Enable static application security testing (OpenGrep plugin).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Enable all scanner plugins.",
    )

    return parser


def _handle_status() -> int:
    """Handle --status command.

    Shows scanner plugin status and validation results.

    Returns:
        Exit code (0 for success).
    """
    home = get_lucidscan_home()
    paths = LucidscanPaths(home)
    platform_info = get_platform_info()

    print(f"lucidscan version: {_get_version()}")
    print(f"Platform: {platform_info.os}-{platform_info.arch}")
    print(f"Binary cache: {home}/bin/")
    print()

    # Validate tools
    print("Scanner plugin status:")
    validation = validate_tools(paths)

    def _status_symbol(status: ToolStatus) -> str:
        if status == ToolStatus.PRESENT:
            return "✓ installed"
        elif status == ToolStatus.MISSING:
            return "✗ not downloaded (will download on first use)"
        else:
            return "✗ not executable"

    print(f"  trivy:    {_status_symbol(validation.trivy)}")
    print(f"  opengrep: {_status_symbol(validation.opengrep)}")
    print(f"  checkov:  {_status_symbol(validation.checkov)}")

    if not validation.all_valid():
        print()
        print("Scanner binaries are downloaded automatically on first use.")

    return EXIT_SUCCESS


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entrypoint.

    Returns an exit code suitable for use as a console script.
    """

    parser = build_parser()

    # Handle --help specially to return 0
    if argv is not None:
        argv_list = list(argv)
        if "--help" in argv_list or "-h" in argv_list:
            parser.print_help()
            return EXIT_SUCCESS
    else:
        argv_list = None

    args = parser.parse_args(argv_list)

    # Configure logging as early as possible.
    configure_logging(debug=args.debug, verbose=args.verbose, quiet=args.quiet)

    if args.version:
        print(_get_version())
        return EXIT_SUCCESS

    if args.status:
        return _handle_status()

    # Scanner execution
    if any([args.sca, args.container, args.iac, args.sast, args.all]):
        print("lucidscan: scanner plugin execution is not implemented yet.")
        print("Scanner plugins will automatically download their binaries on first use.")
        return EXIT_SUCCESS

    # If no scanners are selected, show help to guide users.
    parser.print_help()
    return EXIT_SUCCESS


if __name__ == "__main__":  # pragma: no cover - exercised via console script
    raise SystemExit(main())
