"""
Bootstrap module for lucidscan tool bundle management.

This module handles:
- Platform detection (OS + architecture)
- Tool bundle directory management (~/.lucidscan)
- Bundle download and extraction
- Tool validation (trivy, semgrep, checkov)
"""

from lucidscan.bootstrap.platform import get_platform_info, PlatformInfo
from lucidscan.bootstrap.paths import get_lucidscan_home, LucidscanPaths
from lucidscan.bootstrap.bundle import BundleManager
from lucidscan.bootstrap.validation import validate_tools, ToolValidationResult

__all__ = [
    "get_platform_info",
    "PlatformInfo",
    "get_lucidscan_home",
    "LucidscanPaths",
    "BundleManager",
    "validate_tools",
    "ToolValidationResult",
]

