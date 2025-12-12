"""Tool validation for lucidscan bootstrap.

Validates that required scanner tools are present and executable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

from lucidscan.bootstrap.paths import LucidscanPaths
from lucidscan.core.logging import get_logger

LOGGER = get_logger(__name__)


class ToolStatus(str, Enum):
    """Status of a tool binary."""

    PRESENT = "present"
    MISSING = "missing"
    NOT_EXECUTABLE = "not_executable"


@dataclass
class ToolValidationResult:
    """Result of validating all required tools.

    Attributes:
        trivy: Status of trivy binary.
        semgrep: Status of semgrep binary.
        checkov: Status of checkov binary.
    """

    trivy: ToolStatus
    semgrep: ToolStatus
    checkov: ToolStatus

    def all_valid(self) -> bool:
        """Check if all tools are present and executable."""
        return (
            self.trivy == ToolStatus.PRESENT
            and self.semgrep == ToolStatus.PRESENT
            and self.checkov == ToolStatus.PRESENT
        )

    def missing_tools(self) -> List[str]:
        """Return list of tools that are missing or not executable."""
        missing = []
        if self.trivy != ToolStatus.PRESENT:
            missing.append("trivy")
        if self.semgrep != ToolStatus.PRESENT:
            missing.append("semgrep")
        if self.checkov != ToolStatus.PRESENT:
            missing.append("checkov")
        return missing

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for JSON serialization."""
        return {
            "trivy": self.trivy.value,
            "semgrep": self.semgrep.value,
            "checkov": self.checkov.value,
        }


def validate_tool(path: Path) -> ToolStatus:
    """Validate a single tool binary.

    Args:
        path: Path to the tool binary.

    Returns:
        ToolStatus indicating whether the tool is present and executable.
    """
    if not path.exists():
        return ToolStatus.MISSING

    # Check if executable
    if not os.access(path, os.X_OK):
        return ToolStatus.NOT_EXECUTABLE

    return ToolStatus.PRESENT


def validate_tools(paths: LucidscanPaths) -> ToolValidationResult:
    """Validate all required scanner tools.

    Checks that trivy, semgrep, and checkov are present and executable
    in the expected locations under ~/.lucidscan.

    Args:
        paths: LucidscanPaths instance pointing to the tool bundle.

    Returns:
        ToolValidationResult with status of each tool.
    """
    LOGGER.debug("Validating tool installations...")

    trivy_status = validate_tool(paths.trivy_bin)
    if trivy_status != ToolStatus.PRESENT:
        LOGGER.debug(f"Trivy: {trivy_status.value} at {paths.trivy_bin}")

    semgrep_status = validate_tool(paths.semgrep_bin)
    if semgrep_status != ToolStatus.PRESENT:
        LOGGER.debug(f"Semgrep: {semgrep_status.value} at {paths.semgrep_bin}")

    checkov_status = validate_tool(paths.checkov_bin)
    if checkov_status != ToolStatus.PRESENT:
        LOGGER.debug(f"Checkov: {checkov_status.value} at {paths.checkov_bin}")

    result = ToolValidationResult(
        trivy=trivy_status,
        semgrep=semgrep_status,
        checkov=checkov_status,
    )

    if result.all_valid():
        LOGGER.debug("All tools validated successfully.")
    else:
        LOGGER.debug(f"Missing/invalid tools: {result.missing_tools()}")

    return result

