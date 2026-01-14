"""Tests for pipeline executor."""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.config.models import LucidScanConfig, PipelineConfig
from lucidscan.core.models import ScanContext, ScanDomain, Severity, UnifiedIssue
from lucidscan.pipeline.executor import PipelineConfig as ExecutorPipelineConfig
from lucidscan.pipeline.executor import PipelineExecutor
from lucidscan.pipeline.parallel import ScannerResult


class TestPipelineConfig:
    """Tests for PipelineConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default values for PipelineConfig."""
        config = ExecutorPipelineConfig()
        assert config.sequential_scanners is False
        assert config.max_workers == 4
        assert config.enricher_order == []

    def test_custom_values(self) -> None:
        """Test custom values for PipelineConfig."""
        config = ExecutorPipelineConfig(
            sequential_scanners=True,
            max_workers=8,
            enricher_order=["dedup", "epss"],
        )
        assert config.sequential_scanners is True
        assert config.max_workers == 8
        assert config.enricher_order == ["dedup", "epss"]


class TestPipelineExecutor:
    """Tests for PipelineExecutor."""

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test config."""
        return LucidScanConfig()

    @pytest.fixture
    def context(self, tmp_path: Path, config: LucidScanConfig) -> ScanContext:
        """Create a test scan context."""
        return ScanContext(
            project_root=tmp_path,
            paths=[tmp_path],
            enabled_domains=[ScanDomain.SCA],
            config=config,
        )

    def test_execute_returns_scan_result(
        self, config: LucidScanConfig, context: ScanContext
    ) -> None:
        """Test that execute returns a ScanResult."""
        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan:
            mock_scan.return_value = ([], [])

            executor = PipelineExecutor(config, lucidscan_version="1.0.0")
            result = executor.execute([], context)

            assert result is not None
            assert result.metadata is not None
            assert result.summary is not None

    def test_execute_includes_metadata(
        self, config: LucidScanConfig, context: ScanContext
    ) -> None:
        """Test that execute includes proper metadata."""
        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan:
            mock_scan.return_value = ([], [])

            executor = PipelineExecutor(config, lucidscan_version="1.0.0")
            result = executor.execute([], context)

            assert result.metadata is not None
            assert result.metadata.lucidscan_version == "1.0.0"
            assert result.metadata.project_root == str(context.project_root)
            assert result.metadata.duration_ms >= 0

    def test_execute_computes_summary(
        self, config: LucidScanConfig, context: ScanContext
    ) -> None:
        """Test that execute computes a summary."""
        mock_issue = UnifiedIssue(
            id="test-1",
            scanner=ScanDomain.SCA,
            source_tool="test",
            severity=Severity.HIGH,
            title="Test",
            description="Test issue",
        )

        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan:
            mock_scan.return_value = ([mock_issue], [])

            executor = PipelineExecutor(config)
            result = executor.execute([], context)

            assert result.summary is not None
            assert result.summary.total == 1
            assert result.summary.by_severity.get("high", 0) == 1

    def test_enrichers_run_in_order(
        self, tmp_path: Path
    ) -> None:
        """Test that enrichers execute in configured order."""
        config = LucidScanConfig(
            pipeline=PipelineConfig(enrichers=["first", "second"]),
        )
        context = ScanContext(
            project_root=tmp_path,
            paths=[tmp_path],
            enabled_domains=[ScanDomain.SCA],
            config=config,
        )

        call_order: List[str] = []

        def mock_enricher(name: str) -> MagicMock:
            enricher = MagicMock()
            enricher.name = name

            def enrich_fn(
                issues: List[UnifiedIssue], ctx: ScanContext
            ) -> List[UnifiedIssue]:
                call_order.append(name)
                return issues

            enricher.enrich = enrich_fn
            return enricher

        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan, patch(
            "lucidscan.plugins.enrichers.get_enricher_plugin",
            side_effect=mock_enricher,
        ):
            mock_scan.return_value = ([], [])

            executor = PipelineExecutor(config)
            executor.execute([], context)

            assert call_order == ["first", "second"]

    def test_missing_enricher_skipped(
        self, config: LucidScanConfig, context: ScanContext
    ) -> None:
        """Test that missing enricher is skipped with warning."""
        pipeline_config = ExecutorPipelineConfig(
            enricher_order=["missing", "also_missing"]
        )

        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan, patch(
            "lucidscan.plugins.enrichers.get_enricher_plugin",
            return_value=None,
        ):
            mock_scan.return_value = ([], [])

            executor = PipelineExecutor(config, pipeline_config)
            # Should not raise
            result = executor.execute([], context)

            assert result is not None

    def test_enricher_exception_continues_pipeline(
        self, config: LucidScanConfig, context: ScanContext
    ) -> None:
        """Test that enricher exception doesn't stop the pipeline."""
        pipeline_config = ExecutorPipelineConfig(enricher_order=["failing"])

        failing_enricher = MagicMock()
        failing_enricher.name = "failing"
        failing_enricher.enrich.side_effect = RuntimeError("Enricher failed")

        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan, patch(
            "lucidscan.plugins.enrichers.get_enricher_plugin",
            return_value=failing_enricher,
        ):
            mock_scan.return_value = ([], [])

            executor = PipelineExecutor(config, pipeline_config)
            # Should not raise
            result = executor.execute([], context)

            assert result is not None

    def test_scanner_results_in_metadata(
        self, config: LucidScanConfig, context: ScanContext
    ) -> None:
        """Test that scanner results are included in metadata."""
        scanner_result = ScannerResult(
            scanner_name="test",
            scanner_version="1.0.0",
            domains=["sca"],
            success=True,
        )

        with patch.object(
            PipelineExecutor, "_execute_scanners"
        ) as mock_scan:
            mock_scan.return_value = ([], [scanner_result])

            executor = PipelineExecutor(config)
            result = executor.execute(["test"], context)

            assert result.metadata is not None
            assert len(result.metadata.scanners_used) == 1
            assert result.metadata.scanners_used[0]["name"] == "test"
            assert result.metadata.scanners_used[0]["version"] == "1.0.0"
