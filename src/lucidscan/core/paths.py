"""Path utilities for determining scan targets.

Provides shared logic for determining which files/directories to scan
based on user input and git status.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from lucidscan.core.git import get_changed_files
from lucidscan.core.logging import get_logger

LOGGER = get_logger(__name__)


def determine_scan_paths(
    project_root: Path,
    files: Optional[List[str]] = None,
    all_files: bool = False,
) -> List[Path]:
    """Determine which paths to scan based on arguments.

    Priority:
    1. If `files` is provided, scan only those specific files
    2. If `all_files` is True, scan entire project
    3. Otherwise, scan only changed files (uncommitted changes)

    Args:
        project_root: Project root directory.
        files: Optional list of specific files to scan (relative or absolute).
        all_files: If True, scan entire project.

    Returns:
        List of paths to scan.
    """
    # If specific files are provided, use those
    if files:
        paths = []
        for file_path in files:
            path = Path(file_path)
            if not path.is_absolute():
                path = project_root / path
            path = path.resolve()
            if path.exists():
                paths.append(path)
            else:
                LOGGER.warning(f"File not found: {file_path}")
        if paths:
            LOGGER.info(f"Scanning {len(paths)} specified file(s)")
            return paths
        # Fall through to full scan if no valid files
        LOGGER.warning("No valid files specified, falling back to full scan")
        return [project_root]

    # If all_files is specified, scan entire project
    if all_files:
        LOGGER.info("Scanning entire project")
        return [project_root]

    # Default: scan only changed files
    changed_files = get_changed_files(project_root)
    if changed_files is not None and len(changed_files) > 0:
        LOGGER.info(f"Scanning {len(changed_files)} changed file(s)")
        return changed_files

    # Fall back based on git status
    if changed_files is not None and len(changed_files) == 0:
        LOGGER.info("No changed files detected, nothing to scan")
        return []  # Return empty list - no files to scan
    else:
        # Not a git repo or git command failed
        LOGGER.info("Not a git repository, scanning entire project")
        return [project_root]
