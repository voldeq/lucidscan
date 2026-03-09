"""Tool validation for lucidshark bootstrap.

Validates that scanner plugin tools are present and executable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List

from lucidshark.core.logging import get_logger

LOGGER = get_logger(__name__)


class ToolStatus(str, Enum):
    """Status of a tool binary."""

    PRESENT = "present"
    MISSING = "missing"
    NOT_EXECUTABLE = "not_executable"


@dataclass
class PluginValidationResult:
    """Result of validating scanner plugin tools.

    Stores validation status for each discovered plugin by name.
    """

    statuses: Dict[str, ToolStatus] = field(default_factory=dict)

    def all_valid(self) -> bool:
        """Check if all validated plugins are present and executable."""
        if not self.statuses:
            return True
        return all(status == ToolStatus.PRESENT for status in self.statuses.values())

    def missing_plugins(self) -> List[str]:
        """Return list of plugins that are missing or not executable."""
        return [
            name
            for name, status in self.statuses.items()
            if status != ToolStatus.PRESENT
        ]

    def get_status(self, plugin_name: str) -> ToolStatus:
        """Get status for a specific plugin."""
        return self.statuses.get(plugin_name, ToolStatus.MISSING)

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for JSON serialization."""
        return {name: status.value for name, status in self.statuses.items()}


def validate_binary(path: Path) -> ToolStatus:
    """Validate a single binary file.

    Args:
        path: Path to the binary file.

    Returns:
        ToolStatus indicating whether the binary is present and executable.
    """
    if not path.exists():
        return ToolStatus.MISSING

    # Check if executable
    if not os.access(path, os.X_OK):
        return ToolStatus.NOT_EXECUTABLE

    return ToolStatus.PRESENT
