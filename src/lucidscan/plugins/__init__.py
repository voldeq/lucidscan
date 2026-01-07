"""Plugin infrastructure for lucidscan.

This package provides the plugin discovery and management infrastructure
for all plugin types:
- Scanner plugins (lucidscan.scanners) - Security scanners
- Linter plugins (lucidscan.linters) - Code linting
- Type checker plugins (lucidscan.type_checkers) - Type checking
- Test runner plugins (lucidscan.test_runners) - Test execution
- Coverage plugins (lucidscan.coverage) - Coverage analysis
- Enricher plugins (lucidscan.enrichers) - Post-processing
- Reporter plugins (lucidscan.reporters) - Output formatting

Plugins are discovered via Python entry points.
"""

from lucidscan.plugins.discovery import (
    discover_plugins,
    get_plugin,
    list_available_plugins,
    SCANNER_ENTRY_POINT_GROUP,
    ENRICHER_ENTRY_POINT_GROUP,
    REPORTER_ENTRY_POINT_GROUP,
    LINTER_ENTRY_POINT_GROUP,
    TYPE_CHECKER_ENTRY_POINT_GROUP,
    TEST_RUNNER_ENTRY_POINT_GROUP,
    COVERAGE_ENTRY_POINT_GROUP,
)

__all__ = [
    "discover_plugins",
    "get_plugin",
    "list_available_plugins",
    "SCANNER_ENTRY_POINT_GROUP",
    "ENRICHER_ENTRY_POINT_GROUP",
    "REPORTER_ENTRY_POINT_GROUP",
    "LINTER_ENTRY_POINT_GROUP",
    "TYPE_CHECKER_ENTRY_POINT_GROUP",
    "TEST_RUNNER_ENTRY_POINT_GROUP",
    "COVERAGE_ENTRY_POINT_GROUP",
]
