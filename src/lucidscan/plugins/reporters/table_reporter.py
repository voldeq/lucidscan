"""Table reporter plugin for lucidscan."""

from __future__ import annotations

from typing import IO, List

from lucidscan.core.models import ScanResult, Severity
from lucidscan.plugins.reporters.base import ReporterPlugin


class TableReporter(ReporterPlugin):
    """Reporter plugin that outputs scan results as a human-readable table.

    Produces a formatted table suitable for terminal display with:
    - Severity-sorted issues
    - Truncated fields for readability
    - Summary statistics at the bottom
    """

    @property
    def name(self) -> str:
        return "table"

    def report(self, result: ScanResult, output: IO[str]) -> None:
        """Format scan result as a table and write to output.

        Args:
            result: The scan result to format.
            output: Output stream to write to.
        """
        lines = self._format_table(result)
        output.write("\n".join(lines))
        output.write("\n")

    def _format_table(self, result: ScanResult) -> List[str]:
        """Format scan result as a human-readable table."""
        lines: List[str] = []

        if not result.issues:
            lines.append("No issues found.")
            return lines

        # Header
        lines.append(f"{'SEVERITY':<10} {'ID':<20} {'DEPENDENCY':<40} {'TITLE'}")
        lines.append("-" * 100)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }

        sorted_issues = sorted(
            result.issues, key=lambda x: severity_order.get(x.severity, 5)
        )

        for issue in sorted_issues:
            sev = issue.severity.value.upper()
            # Use rule_id first, then check metadata for vulnerability_id, fallback to issue id
            rule_id = issue.rule_id or issue.metadata.get("vulnerability_id", issue.id)
            rule_id = rule_id[:20]
            dep = (issue.dependency or "")[:40]
            title = issue.title[:60] if len(issue.title) > 60 else issue.title
            lines.append(f"{sev:<10} {rule_id:<20} {dep:<40} {title}")

        # Summary
        lines.append("")
        lines.append("-" * 100)
        if result.summary:
            lines.append(f"Total: {result.summary.total} issues")
            sev_parts = [
                f"{sev}: {count}"
                for sev, count in result.summary.by_severity.items()
            ]
            if sev_parts:
                lines.append(f"By severity: {', '.join(sev_parts)}")

        return lines
