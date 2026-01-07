"""Base class for reporter plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import IO

from lucidscan.core.models import ScanResult


class ReporterPlugin(ABC):
    """Base class for all reporter plugins.

    Reporter plugins format and output scan results in various formats.
    Each reporter implements a specific output format (JSON, table, SARIF, etc.)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Reporter identifier (e.g., 'json', 'table', 'sarif')."""

    @abstractmethod
    def report(self, result: ScanResult, output: IO[str]) -> None:
        """Format and write the scan result.

        Args:
            result: The aggregated scan result to format.
            output: Output stream to write the formatted result.
        """
