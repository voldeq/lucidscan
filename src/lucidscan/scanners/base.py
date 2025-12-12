from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from lucidscan.core.models import ScanRequest, UnifiedIssue


class ScannerAdapter(ABC):
    """Abstract base class for all scanner adapters.

    Concrete implementations (Trivy, Checkov, Semgrep, etc.) will be added in
    later phases. For Phase 0 we only define the interface.
    """

    @abstractmethod
    def run(self, request: ScanRequest) -> List[UnifiedIssue]:
        """Execute a scan for the given request and return unified issues."""
        raise NotImplementedError


