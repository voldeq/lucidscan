"""Tests for core models."""

from __future__ import annotations

from pathlib import Path

from lucidscan.core.models import ScanRequest, ScanResult, ScannerType, Severity, UnifiedIssue


def test_unified_issue_minimal_construction() -> None:
    issue = UnifiedIssue(
        id="test-1",
        scanner=ScannerType.SCA,
        source_tool="trivy",
        severity=Severity.HIGH,
        title="Example issue",
        description="Example description",
    )

    assert issue.id == "test-1"
    assert issue.scanner is ScannerType.SCA
    assert issue.severity is Severity.HIGH
    assert issue.scanner_metadata == {}


def test_scan_request_and_result_roundtrip() -> None:
    project_root = Path("/tmp/example")
    paths = [project_root / "src"]

    request = ScanRequest(project_root=project_root, paths=paths, enabled_scanners=[ScannerType.SCA])
    issue = UnifiedIssue(
        id="issue-1",
        scanner=ScannerType.SCA,
        source_tool="trivy",
        severity=Severity.LOW,
        title="Low severity issue",
        description="Details",
    )

    result = ScanResult(issues=[issue])

    assert request.enabled_scanners == [ScannerType.SCA]
    assert result.issues[0].id == "issue-1"
    assert result.schema_version.startswith("0.")

