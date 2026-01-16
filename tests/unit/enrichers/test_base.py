"""Tests for enricher plugin base class and discovery."""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from lucidscan.core.models import ScanContext, ScanDomain, Severity, UnifiedIssue
from lucidscan.plugins.enrichers.base import EnricherPlugin


class ConcreteEnricher(EnricherPlugin):
    """Concrete enricher for testing."""

    @property
    def name(self) -> str:
        return "test-enricher"

    def enrich(
        self,
        issues: List[UnifiedIssue],
        context: ScanContext,
    ) -> List[UnifiedIssue]:
        # Add metadata to each issue
        for issue in issues:
            issue.metadata["enriched"] = True
        return issues


class FilteringEnricher(EnricherPlugin):
    """Enricher that filters issues."""

    @property
    def name(self) -> str:
        return "filter-enricher"

    def enrich(
        self,
        issues: List[UnifiedIssue],
        context: ScanContext,
    ) -> List[UnifiedIssue]:
        # Only return high+ severity issues
        return [
            issue
            for issue in issues
            if issue.severity in (Severity.CRITICAL, Severity.HIGH)
        ]


class TestEnricherPluginABC:
    """Tests for EnricherPlugin abstract base class."""

    def test_requires_name_property(self) -> None:
        """Test that name property is required."""
        enricher = ConcreteEnricher()
        assert enricher.name == "test-enricher"

    def test_requires_enrich_method(self) -> None:
        """Test that enrich method is required."""
        enricher = ConcreteEnricher()
        assert callable(enricher.enrich)

    def test_cannot_instantiate_abstract_class(self) -> None:
        """Test that EnricherPlugin cannot be instantiated directly."""
        with pytest.raises(TypeError):
            EnricherPlugin()  # type: ignore


class TestConcreteEnricher:
    """Tests for a concrete enricher implementation."""

    @pytest.fixture
    def context(self, tmp_path: Path) -> ScanContext:
        """Create a test scan context."""
        return ScanContext(
            project_root=tmp_path,
            paths=[tmp_path],
            enabled_domains=[ScanDomain.SCA],
        )

    @pytest.fixture
    def sample_issues(self) -> List[UnifiedIssue]:
        """Create sample issues for testing."""
        return [
            UnifiedIssue(
                id="issue-1",
                domain=ScanDomain.SCA,
                source_tool="test",
                severity=Severity.HIGH,
                rule_id="CVE-2021-1234",
                title="High Issue",
                description="A high severity issue",
            ),
            UnifiedIssue(
                id="issue-2",
                domain=ScanDomain.SCA,
                source_tool="test",
                severity=Severity.LOW,
                rule_id="CVE-2021-5678",
                title="Low Issue",
                description="A low severity issue",
            ),
        ]

    def test_enrich_modifies_issues(
        self,
        context: ScanContext,
        sample_issues: List[UnifiedIssue],
    ) -> None:
        """Test that enricher can modify issues."""
        enricher = ConcreteEnricher()
        enriched = enricher.enrich(sample_issues, context)

        assert len(enriched) == 2
        for issue in enriched:
            assert issue.metadata.get("enriched") is True

    def test_enrich_can_filter_issues(
        self,
        context: ScanContext,
        sample_issues: List[UnifiedIssue],
    ) -> None:
        """Test that enricher can filter issues."""
        enricher = FilteringEnricher()
        enriched = enricher.enrich(sample_issues, context)

        assert len(enriched) == 1
        assert enriched[0].id == "issue-1"
        assert enriched[0].severity == Severity.HIGH

    def test_enrich_preserves_original_issues(
        self,
        context: ScanContext,
        sample_issues: List[UnifiedIssue],
    ) -> None:
        """Test that enricher can return issues unchanged."""
        # Create an enricher that does nothing
        class NoOpEnricher(EnricherPlugin):
            @property
            def name(self) -> str:
                return "noop"

            def enrich(
                self,
                issues: List[UnifiedIssue],
                context: ScanContext,
            ) -> List[UnifiedIssue]:
                return issues

        enricher = NoOpEnricher()
        enriched = enricher.enrich(sample_issues, context)

        assert enriched == sample_issues

    def test_enrich_receives_context(
        self,
        context: ScanContext,
        sample_issues: List[UnifiedIssue],
    ) -> None:
        """Test that enricher receives scan context."""
        received_context = None

        class ContextCapturingEnricher(EnricherPlugin):
            @property
            def name(self) -> str:
                return "context-capture"

            def enrich(
                self,
                issues: List[UnifiedIssue],
                ctx: ScanContext,
            ) -> List[UnifiedIssue]:
                nonlocal received_context
                received_context = ctx
                return issues

        enricher = ContextCapturingEnricher()
        enricher.enrich(sample_issues, context)

        assert received_context is context
        assert received_context.project_root == context.project_root
