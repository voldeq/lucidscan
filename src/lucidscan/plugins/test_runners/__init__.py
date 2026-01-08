"""Test runner plugins for lucidscan.

This module provides test runner integrations for the quality pipeline.
Test runners are discovered via the lucidscan.test_runners entry point group.
"""

from lucidscan.plugins.test_runners.base import TestRunnerPlugin, TestResult
from lucidscan.plugins.discovery import (
    discover_plugins,
    TEST_RUNNER_ENTRY_POINT_GROUP,
)


def discover_test_runner_plugins():
    """Discover all installed test runner plugins.

    Returns:
        Dictionary mapping plugin names to plugin classes.
    """
    return discover_plugins(TEST_RUNNER_ENTRY_POINT_GROUP, TestRunnerPlugin)


__all__ = [
    "TestRunnerPlugin",
    "TestResult",
    "discover_test_runner_plugins",
]
