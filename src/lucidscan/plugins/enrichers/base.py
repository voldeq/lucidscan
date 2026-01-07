"""Base class for enricher plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from lucidscan.core.models import ScanContext, UnifiedIssue


class EnricherPlugin(ABC):
    """Base class for all enricher plugins.

    Enricher plugins process issues after scanning, adding additional
    context, metadata, or performing transformations. They run sequentially
    in the configured order, with each enricher receiving the output of
    the previous one.

    Example enrichers:
    - Deduplication: Remove duplicate issues across scanners
    - EPSS scoring: Add exploit prediction scores
    - KEV tagging: Mark known exploited vulnerabilities
    - AI explanation: Add LLM-generated explanations

    Enricher constraints:
    - Enrichers MUST NOT modify severity levels set by scanners
    - Enrichers MUST NOT affect exit codes (that's the CLI's responsibility)
    - Enrichers MAY filter, augment, or reorder issues
    - Enrichers SHOULD preserve scanner_metadata from original issues
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Enricher identifier (e.g., 'dedup', 'epss', 'kev').

        This name is used for:
        - Plugin discovery via entry points
        - Configuration in .lucidscan.yml
        - Logging and error messages
        """

    @abstractmethod
    def enrich(
        self,
        issues: List["UnifiedIssue"],
        context: "ScanContext",
    ) -> List["UnifiedIssue"]:
        """Process and enrich issues.

        Args:
            issues: List of issues from scanner execution (or previous enricher).
            context: Scan context with project info and configuration.

        Returns:
            Enriched list of issues. May be modified, filtered, augmented,
            or returned unchanged.

        Raises:
            Any exception raised will be logged and the enricher skipped,
            with the pipeline continuing with unenriched issues.
        """
