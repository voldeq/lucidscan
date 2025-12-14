"""
Bootstrap module for lucidscan plugin binary management.

This module handles:
- Platform detection (OS + architecture)
- Plugin binary directory management (~/.lucidscan/bin/)
- Tool validation (trivy, opengrep, checkov)

Each scanner plugin is responsible for downloading its own binary
using the utilities provided by this module.
"""

from lucidscan.bootstrap.platform import get_platform_info, PlatformInfo
from lucidscan.bootstrap.paths import get_lucidscan_home, LucidscanPaths
from lucidscan.bootstrap.validation import validate_tools, ToolValidationResult

__all__ = [
    "get_platform_info",
    "PlatformInfo",
    "get_lucidscan_home",
    "LucidscanPaths",
    "validate_tools",
    "ToolValidationResult",
]

