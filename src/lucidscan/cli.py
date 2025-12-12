from __future__ import annotations

import argparse
import sys
from typing import Iterable, List, Optional

from importlib.metadata import version, PackageNotFoundError

from lucidscan.core.logging import configure_logging, get_logger
from lucidscan.bootstrap.paths import get_lucidscan_home, LucidscanPaths
from lucidscan.bootstrap.platform import get_platform_info, PlatformInfo
from lucidscan.bootstrap.bundle import BundleManager, BundleError
from lucidscan.bootstrap.validation import validate_tools, ToolValidationResult, ToolStatus


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
        description="LucidShark unified security scanner.",
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
        choices=["json", "table", "summary"],
        default="json",
        help="Output format (placeholder; defaults to json).",
    )

    # Bootstrap / tool management flags
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Initialize the tool bundle (~/.lucidscan) if not already present.",
    )
    parser.add_argument(
        "--update-tools",
        action="store_true",
        help="Force re-download and update of the tool bundle.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show tool bundle status and validation results.",
    )

    # Scanner domain flags (stubs until Phase 2+)
    parser.add_argument(
        "--sca",
        action="store_true",
        help="Enable Software Composition Analysis (not implemented yet).",
    )
    parser.add_argument(
        "--container",
        action="store_true",
        help="Enable container image scanning (not implemented yet).",
    )
    parser.add_argument(
        "--iac",
        action="store_true",
        help="Enable Infrastructure-as-Code scanning (not implemented yet).",
    )
    parser.add_argument(
        "--sast",
        action="store_true",
        help="Enable static application security testing (not implemented yet).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Enable all scanners (not implemented yet).",
    )

    return parser


def _handle_bootstrap(force: bool = False) -> int:
    """Handle --bootstrap or --update-tools command.

    Args:
        force: If True, force re-download even if already initialized.

    Returns:
        Exit code (0 for success, 4 for bootstrap failure).
    """
    try:
        home = get_lucidscan_home()
        paths = LucidscanPaths(home)
        platform_info = get_platform_info()

        manager = BundleManager(paths=paths, platform_info=platform_info)

        if force:
            print("Updating lucidscan tool bundle...")
        else:
            print("Initializing lucidscan tool bundle...")

        manager.bootstrap(force=force)

        # Validate tools after bootstrap
        validation = validate_tools(paths)
        if validation.all_valid():
            print("Tool bundle initialized successfully.")
            print(f"Location: {home}")
            return EXIT_SUCCESS
        else:
            print("Warning: Some tools may not be fully functional:", file=sys.stderr)
            for tool in validation.missing_tools():
                print(f"  - {tool}: not properly installed", file=sys.stderr)
            return EXIT_SUCCESS  # Bootstrap succeeded, just validation warning

    except BundleError as e:
        print(f"Bootstrap failed: {e}", file=sys.stderr)
        return EXIT_BOOTSTRAP_FAILURE
    except ValueError as e:
        # Platform detection error
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_BOOTSTRAP_FAILURE


def _handle_status() -> int:
    """Handle --status command.

    Shows tool bundle status and validation results.

    Returns:
        Exit code (0 for success).
    """
    home = get_lucidscan_home()
    paths = LucidscanPaths(home)

    print(f"lucidscan version: {_get_version()}")
    print(f"Tool bundle location: {home}")
    print()

    # Check if initialized
    if not paths.is_initialized():
        print("Status: NOT INITIALIZED")
        print()
        print("Run 'lucidscan --bootstrap' to initialize the tool bundle.")
        return EXIT_SUCCESS

    print("Status: INITIALIZED")
    print()

    # Show versions if available
    from lucidscan.bootstrap.bundle import BundleManager
    platform_info = get_platform_info()
    manager = BundleManager(paths=paths, platform_info=platform_info)
    versions = manager.read_versions()

    if versions:
        print("Installed versions:")
        print(f"  trivy:   {versions.trivy or 'unknown'}")
        print(f"  semgrep: {versions.semgrep or 'unknown'}")
        print(f"  checkov: {versions.checkov or 'unknown'}")
        print(f"  bundle:  {versions.bundle_version or 'unknown'}")
        print()

    # Validate tools
    print("Tool validation:")
    validation = validate_tools(paths)

    def _status_symbol(status: ToolStatus) -> str:
        if status == ToolStatus.PRESENT:
            return "✓"
        elif status == ToolStatus.MISSING:
            return "✗ (missing)"
        else:
            return "✗ (not executable)"

    print(f"  trivy:   {_status_symbol(validation.trivy)}")
    print(f"  semgrep: {_status_symbol(validation.semgrep)}")
    print(f"  checkov: {_status_symbol(validation.checkov)}")

    if not validation.all_valid():
        print()
        print("Some tools are not available. Run 'lucidscan --update-tools' to fix.")

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

    # Handle bootstrap commands
    if args.update_tools:
        return _handle_bootstrap(force=True)

    if args.bootstrap:
        return _handle_bootstrap(force=False)

    if args.status:
        return _handle_status()

    # For Phase 1, we only acknowledge scanner flags and report that they are
    # not yet implemented.
    if any([args.sca, args.container, args.iac, args.sast, args.all]):
        print("lucidscan: scanner execution is not implemented yet (Phase 0 skeleton).")
        return EXIT_SUCCESS

    # If no scanners are selected, show help to guide users.
    parser.print_help()
    return EXIT_SUCCESS


if __name__ == "__main__":  # pragma: no cover - exercised via console script
    raise SystemExit(main())
