"""Tests for core models."""

from __future__ import annotations

from pathlib import Path

from lucidscan.core.models import ScanContext, ScanDomain, ScanResult, Severity, UnifiedIssue


def test_unified_issue_minimal_construction() -> None:
    issue = UnifiedIssue(
        id="test-1",
        domain=ScanDomain.SCA,
        source_tool="trivy",
        severity=Severity.HIGH,
        rule_id="CVE-2021-1234",
        title="Example issue",
        description="Example description",
    )

    assert issue.id == "test-1"
    assert issue.domain is ScanDomain.SCA
    assert issue.severity is Severity.HIGH
    assert issue.rule_id == "CVE-2021-1234"
    assert issue.metadata == {}


def test_scan_context_and_result_roundtrip() -> None:
    project_root = Path("/tmp/example")
    paths = [project_root / "src"]

    context = ScanContext(project_root=project_root, paths=paths, enabled_domains=[ScanDomain.SCA])
    issue = UnifiedIssue(
        id="issue-1",
        domain=ScanDomain.SCA,
        source_tool="trivy",
        severity=Severity.LOW,
        rule_id="CVE-2021-5678",
        title="Low severity issue",
        description="Details",
    )

    result = ScanResult(issues=[issue])

    assert context.enabled_domains == [ScanDomain.SCA]
    assert result.issues[0].id == "issue-1"
    assert result.schema_version.startswith("1.")

