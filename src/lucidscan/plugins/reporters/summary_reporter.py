"""Summary reporter plugin for lucidscan."""

from __future__ import annotations

from typing import IO, List

from lucidscan.core.models import ScanResult
from lucidscan.plugins.reporters.base import ReporterPlugin


class SummaryReporter(ReporterPlugin):
    """Reporter plugin that outputs a brief scan summary.

    Produces a concise summary with:
    - Total issue count
    - Breakdown by severity
    - Breakdown by scanner domain
    - Scan duration and project info
    """

    @property
    def name(self) -> str:
        return "summary"

    def report(self, result: ScanResult, output: IO[str]) -> None:
        """Format scan result as a summary and write to output.

        Args:
            result: The scan result to format.
            output: Output stream to write to.
        """
        lines = self._format_summary(result)
        output.write("\n".join(lines))
        output.write("\n")

    def _format_summary(self, result: ScanResult) -> List[str]:
        """Format scan result as a brief summary."""
        lines: List[str] = []

        if result.summary:
            lines.append(f"Total issues: {result.summary.total}")

            if result.summary.by_severity:
                lines.append("\nBy severity:")
                for sev in ["critical", "high", "medium", "low", "info"]:
                    count = result.summary.by_severity.get(sev, 0)
                    if count > 0:
                        lines.append(f"  {sev.upper()}: {count}")

            if result.summary.by_scanner:
                lines.append("\nBy scanner domain:")
                for scanner, count in result.summary.by_scanner.items():
                    lines.append(f"  {scanner.upper()}: {count}")
        else:
            lines.append("No summary available.")

        if result.metadata:
            lines.append(f"\nScan duration: {result.metadata.duration_ms}ms")
            lines.append(f"Project: {result.metadata.project_root}")

        return lines
