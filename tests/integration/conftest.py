"""Pytest configuration and fixtures for integration tests."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from lucidscan.scanners.trivy import TrivyScanner
from lucidscan.bootstrap.paths import LucidscanPaths


def _ensure_trivy_downloaded() -> bool:
    """Ensure Trivy binary is downloaded. Returns True if available."""
    scanner = TrivyScanner()
    try:
        scanner.ensure_binary()
        return True
    except Exception:
        return False


def _is_trivy_in_path() -> bool:
    """Check if trivy is in PATH."""
    return shutil.which("trivy") is not None


def _is_docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# Download Trivy at module load time so skipif markers work correctly
_trivy_available = _ensure_trivy_downloaded() or _is_trivy_in_path()
_docker_available = _is_docker_available()

# Pytest markers for conditional test execution
trivy_available = pytest.mark.skipif(
    not _trivy_available,
    reason="Trivy binary not available and could not be downloaded"
)

docker_available = pytest.mark.skipif(
    not _docker_available,
    reason="Docker not available or not running"
)


@pytest.fixture
def project_root() -> Path:
    """Return the lucidshark project root directory."""
    return Path(__file__).parent.parent.parent


@pytest.fixture
def trivy_scanner() -> TrivyScanner:
    """Return a TrivyScanner instance."""
    return TrivyScanner()


@pytest.fixture
def ensure_trivy_binary(trivy_scanner: TrivyScanner) -> Path:
    """Ensure Trivy binary is downloaded and return its path."""
    return trivy_scanner.ensure_binary()
