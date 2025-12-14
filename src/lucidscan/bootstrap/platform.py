"""Platform detection for lucidscan scanner plugins.

Detects OS and architecture to determine which scanner binaries to download.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Optional

# Supported operating systems (lowercase)
SUPPORTED_OS = frozenset({"darwin", "linux", "windows"})

# Supported architectures (normalized)
SUPPORTED_ARCH = frozenset({"amd64", "arm64"})

# Architecture normalization map
_ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
}


def normalize_arch(machine: str) -> Optional[str]:
    """Normalize architecture string to standard form.

    Args:
        machine: Raw architecture string from platform.machine()

    Returns:
        Normalized architecture string or None if unknown.
    """
    return _ARCH_MAP.get(machine.lower())


def detect_os() -> str:
    """Detect the current operating system.

    Returns:
        Lowercase OS name (darwin, linux, windows).

    Raises:
        ValueError: If the OS is not supported.
    """
    system = platform.system().lower()
    if system not in SUPPORTED_OS:
        raise ValueError(
            f"Unsupported operating system: {platform.system()}. "
            f"Supported: {', '.join(sorted(SUPPORTED_OS))}"
        )
    return system


def detect_arch() -> str:
    """Detect the current CPU architecture.

    Returns:
        Normalized architecture string (amd64 or arm64).

    Raises:
        ValueError: If the architecture is not supported.
    """
    machine = platform.machine()
    normalized = normalize_arch(machine)
    if normalized is None:
        raise ValueError(
            f"Unsupported architecture: {machine}. "
            f"Supported: {', '.join(sorted(SUPPORTED_ARCH))}"
        )
    return normalized


@dataclass(frozen=True)
class PlatformInfo:
    """Information about the current platform.

    Attributes:
        os: Operating system (darwin, linux, windows).
        arch: CPU architecture (amd64, arm64).
    """

    os: str
    arch: str

    @property
    def bundle_name(self) -> str:
        """Return the bundle name suffix for this platform.

        Example: "darwin-arm64", "linux-amd64"
        """
        return f"{self.os}-{self.arch}"

    def is_supported(self) -> bool:
        """Check if this platform is supported."""
        return self.os in SUPPORTED_OS and self.arch in SUPPORTED_ARCH


def get_platform_info() -> PlatformInfo:
    """Detect and return current platform information.

    Returns:
        PlatformInfo with detected OS and architecture.

    Raises:
        ValueError: If the platform is not supported.
    """
    return PlatformInfo(os=detect_os(), arch=detect_arch())

