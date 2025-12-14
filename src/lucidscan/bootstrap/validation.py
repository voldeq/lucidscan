"""Tool validation for lucidscan bootstrap.

Validates that required scanner tools are present and executable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List

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
    """Result of validating all required scanner plugin tools.

    Attributes:
        trivy: Status of trivy binary.
        opengrep: Status of opengrep binary.
        checkov: Status of checkov binary.
    """

    trivy: ToolStatus
    opengrep: ToolStatus
    checkov: ToolStatus

    def all_valid(self) -> bool:
        """Check if all tools are present and executable."""
        return (
            self.trivy == ToolStatus.PRESENT
            and self.opengrep == ToolStatus.PRESENT
            and self.checkov == ToolStatus.PRESENT
        )

    def missing_tools(self) -> List[str]:
        """Return list of tools that are missing or not executable."""
        missing = []
        if self.trivy != ToolStatus.PRESENT:
            missing.append("trivy")
        if self.opengrep != ToolStatus.PRESENT:
            missing.append("opengrep")
        if self.checkov != ToolStatus.PRESENT:
            missing.append("checkov")
        return missing

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for JSON serialization."""
        return {
            "trivy": self.trivy.value,
            "opengrep": self.opengrep.value,
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
    """Validate all required scanner plugin tools.

    Checks that trivy, opengrep, and checkov are present and executable
    in the expected locations under ~/.lucidscan/bin/.

    Args:
        paths: LucidscanPaths instance pointing to the plugin binary cache.

    Returns:
        ToolValidationResult with status of each tool.
    """
    LOGGER.debug("Validating scanner plugin binaries...")

    trivy_status = validate_tool(paths.trivy_bin)
    if trivy_status != ToolStatus.PRESENT:
        LOGGER.debug(f"Trivy: {trivy_status.value} at {paths.trivy_bin}")

    opengrep_status = validate_tool(paths.opengrep_bin)
    if opengrep_status != ToolStatus.PRESENT:
        LOGGER.debug(f"OpenGrep: {opengrep_status.value} at {paths.opengrep_bin}")

    checkov_status = validate_tool(paths.checkov_bin)
    if checkov_status != ToolStatus.PRESENT:
        LOGGER.debug(f"Checkov: {checkov_status.value} at {paths.checkov_bin}")

    result = ToolValidationResult(
        trivy=trivy_status,
        opengrep=opengrep_status,
        checkov=checkov_status,
    )

    if result.all_valid():
        LOGGER.debug("All scanner plugin binaries validated successfully.")
    else:
        LOGGER.debug(f"Missing/invalid tools: {result.missing_tools()}")

    return result

