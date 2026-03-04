"""Core logic for applying ignore_issues rules to scan results.

Matches issues by rule_id against configured ignore entries,
tagging matched issues as ignored while tracking expiry and
unmatched entries for warnings.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import List, Set

from lucidshark.config.models import IgnoreIssueEntry
from lucidshark.core.models import UnifiedIssue


def apply_ignore_issues(
    issues: List[UnifiedIssue],
    ignore_entries: List[IgnoreIssueEntry],
) -> List[str]:
    """Tag matching issues as ignored. Returns list of warning messages.

    For each ignore entry:
    - If expired, add a warning and skip it
    - Otherwise, mark all issues with matching rule_id as ignored
    - Track which rule IDs matched; unmatched ones produce a warning

    Args:
        issues: List of issues to process (modified in place).
        ignore_entries: List of ignore rules from config.

    Returns:
        List of warning strings for expired/unmatched entries.
    """
    warnings: List[str] = []
    today = date.today()

    # Build active rule_id -> entry mapping, checking expiry
    active_entries: dict[str, IgnoreIssueEntry] = {}
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
        active_entries[entry.rule_id] = entry

    # Track which rule IDs actually matched
    matched_rule_ids: Set[str] = set()

    # Apply ignores
    for issue in issues:
        if issue.rule_id in active_entries:
            entry = active_entries[issue.rule_id]
            issue.ignored = True
            issue.ignore_reason = entry.reason
            matched_rule_ids.add(issue.rule_id)

    # Warn about unmatched entries
    for rule_id in active_entries:
        if rule_id not in matched_rule_ids:
            warnings.append(
                f"ignore_issues entry for '{rule_id}' did not match any issues"
            )

    return warnings
