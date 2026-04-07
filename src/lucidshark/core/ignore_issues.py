"""Core logic for applying ignore_issues rules to scan results.

Matches issues by rule_id against configured ignore entries,
tagging matched issues as ignored while tracking expiry and
unmatched entries for warnings.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple

import pathspec

from lucidshark.config.models import IgnoreIssueEntry
from lucidshark.core.models import UnifiedIssue


def _normalize_path(file_path: Path, project_root: Path) -> str:
    """Normalize a file path to a forward-slash relative path for pattern matching.

    Args:
        file_path: The file path to normalize.
        project_root: Project root for relative path calculation.

    Returns:
        Forward-slash normalized path string suitable for pathspec matching.
    """
    try:
        resolved = file_path.resolve() if file_path.is_absolute() else file_path
        root_resolved = project_root.resolve()
        rel_path = resolved.relative_to(root_resolved)
    except ValueError:
        # Path is not relative to project root, use as-is
        rel_path = file_path

    # pathspec expects forward-slash paths
    return str(rel_path).replace("\\", "/")


def _matches_spec(
    issue: UnifiedIssue,
    spec: pathspec.PathSpec,
    project_root: Path,
) -> bool:
    """Check if issue's file_path matches the pre-compiled pathspec.

    Args:
        issue: The issue to check.
        spec: Pre-compiled PathSpec for matching.
        project_root: Project root for relative path calculation.

    Returns:
        True if the issue's file path matches the spec, False otherwise.
        Returns False if the issue has no file_path.
    """
    if issue.file_path is None:
        return False  # No file path = can't match paths filter

    rel_str = _normalize_path(issue.file_path, project_root)
    return spec.match_file(rel_str)


def apply_ignore_issues(
    issues: List[UnifiedIssue],
    ignore_entries: List[IgnoreIssueEntry],
    project_root: Optional[Path] = None,
) -> List[str]:
    """Tag matching issues as ignored. Returns list of warning messages.

    For each ignore entry:
    - If expired, add a warning and skip it
    - Otherwise, mark all issues with matching rule_id as ignored
    - If paths are specified, only ignore issues in matching files
    - Track which rule IDs matched; unmatched ones produce a warning

    Args:
        issues: List of issues to process (modified in place).
        ignore_entries: List of ignore rules from config.
        project_root: Project root for path matching. Defaults to cwd.

    Returns:
        List of warning strings for expired/unmatched entries.
    """
    warnings: List[str] = []
    today = date.today()

    if project_root is None:
        project_root = Path.cwd()

    # Build active rule_id -> (entry, compiled_spec) mapping, checking expiry
    # Pre-compile PathSpec objects once per entry for performance
    active_entries: dict[str, Tuple[IgnoreIssueEntry, Optional[pathspec.PathSpec]]] = {}

    for entry in ignore_entries:
        if entry.expires:
            try:
                expires_date = datetime.strptime(entry.expires, "%Y-%m-%d").date()
                if expires_date < today:
                    warnings.append(
                        f"ignore_issues entry for '{entry.rule_id}' expired on "
                        f"{entry.expires} and is no longer suppressing issues"
                    )
                    continue
            except ValueError:
                warnings.append(
                    f"ignore_issues entry for '{entry.rule_id}' has invalid "
                    f"expires date '{entry.expires}', ignoring expiry"
                )

        # Pre-compile PathSpec if paths are specified and non-empty
        compiled_spec: Optional[pathspec.PathSpec] = None
        if entry.paths:
            compiled_spec = pathspec.PathSpec.from_lines("gitignore", entry.paths)

        active_entries[entry.rule_id] = (entry, compiled_spec)

    # Track which rule IDs actually matched
    matched_rule_ids: Set[str] = set()

    # Apply ignores
    for issue in issues:
        if issue.rule_id in active_entries:
            entry, compiled_spec = active_entries[issue.rule_id]

            # Check paths filter if specified (compiled_spec is set when paths is non-empty)
            if compiled_spec is not None:
                if not _matches_spec(issue, compiled_spec, project_root):
                    continue  # Skip - path doesn't match

            issue.ignored = True
            issue.ignore_reason = entry.reason
            matched_rule_ids.add(issue.rule_id)

    # Warn about unmatched entries
    for rule_id in active_entries:
        if rule_id not in matched_rule_ids:
            # Check if this looks like an internal LucidShark ID (tool-hash pattern)
            import re

            if re.match(r"^[a-z]+-[0-9a-f]{16}$", rule_id):
                warnings.append(
                    f"ignore_issues entry for '{rule_id}' did not match any issues. "
                    f"This looks like an internal LucidShark ID. "
                    f"Use the CVE/GHSA identifier from the issue title instead (e.g., CVE-2026-29062), "
                    f"not the internal ID from scan output."
                )
            else:
                warnings.append(
                    f"ignore_issues entry for '{rule_id}' did not match any issues. "
                    f"Verify the rule_id is correct - check scan output for the exact CVE/GHSA/rule code."
                )

    return warnings
