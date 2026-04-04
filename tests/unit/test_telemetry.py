"""Tests for anonymous telemetry module."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from lucidshark import telemetry


@pytest.fixture(autouse=True)
def _reset_telemetry():
    """Reset telemetry state before and after each test."""
    telemetry.reset()
    yield
    telemetry.reset()


@pytest.fixture
def _enable_telemetry(monkeypatch):
    """Ensure telemetry is enabled for the test."""
    monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("CI", raising=False)


@pytest.fixture
def mock_posthog(monkeypatch, tmp_path):
    """Set up enabled telemetry with a mock PostHog client.

    Returns the mock client so tests can inspect captured events.
    """
    monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)

    mock_client = MagicMock()
    monkeypatch.setattr(telemetry, "_get_client", lambda: mock_client)
    return mock_client


# ---------------------------------------------------------------------------
# Fake dataclass helpers — mimic real model shapes without importing them
# ---------------------------------------------------------------------------


@dataclass
class _FakeScanMetadata:
    executed_domains: List[str] = field(default_factory=list)
    scanners_used: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    all_files: bool = False


@dataclass
class _FakeScanSummary:
    total: int = 0
    ignored_total: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_scanner: Dict[str, int] = field(default_factory=dict)


@dataclass
class _FakeCoverageSummary:
    coverage_percentage: float = 0.0
    passed: bool = True


@dataclass
class _FakeDuplicationSummary:
    duplication_percent: float = 0.0
    passed: bool = True


@dataclass
class _FakeToolSkip:
    tool_name: str = "ruff"


@dataclass
class _FakeScanResult:
    metadata: Optional[_FakeScanMetadata] = None
    summary: Optional[_FakeScanSummary] = None
    coverage_summary: Optional[_FakeCoverageSummary] = None
    duplication_summary: Optional[_FakeDuplicationSummary] = None
    tool_skips: List[Any] = field(default_factory=list)


@dataclass
class _FakeProjectConfig:
    name: str = ""
    languages: List[str] = field(default_factory=list)


@dataclass
class _FakeConfig:
    project: _FakeProjectConfig = field(default_factory=_FakeProjectConfig)


@dataclass
class _FakeConfigWithPrivateFields:
    """Config with _config_sources that should be stripped."""

    project: _FakeProjectConfig = field(default_factory=_FakeProjectConfig)
    _config_sources: List[str] = field(default_factory=list)


# ===================================================================
# is_enabled
# ===================================================================


class TestIsEnabled:
    """Tests for telemetry opt-out checks."""

    def test_disabled_by_env_var_zero(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "0")
        assert telemetry.is_enabled() is False

    def test_disabled_by_env_var_false(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "false")
        assert telemetry.is_enabled() is False

    def test_disabled_by_env_var_no(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "no")
        assert telemetry.is_enabled() is False

    def test_disabled_by_env_var_off(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "off")
        assert telemetry.is_enabled() is False

    def test_disabled_by_do_not_track(self, monkeypatch):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.setenv("DO_NOT_TRACK", "1")
        assert telemetry.is_enabled() is False

    def test_disabled_in_ci(self, monkeypatch):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.setenv("CI", "true")
        assert telemetry.is_enabled() is False

    def test_disabled_by_optout_file(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        optout_file = tmp_path / "telemetry-optout"
        optout_file.touch()
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        assert telemetry.is_enabled() is False

    def test_enabled_by_default(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        assert telemetry.is_enabled() is True

    def test_enabled_caches_result(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        assert telemetry.is_enabled() is True
        # Should return cached value even if env changes
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "0")
        assert telemetry.is_enabled() is True  # Still cached as True


# ===================================================================
# _get_anonymous_id
# ===================================================================


class TestAnonymousId:
    """Tests for anonymous ID generation and persistence."""

    def test_generates_uuid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        anon_id = telemetry._get_anonymous_id()
        assert len(anon_id) == 36  # UUID format
        assert "-" in anon_id

    def test_persists_to_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        anon_id = telemetry._get_anonymous_id()

        id_file = tmp_path / "anonymous-id"
        assert id_file.exists()
        assert id_file.read_text().strip() == anon_id

    def test_reads_existing_id(self, tmp_path, monkeypatch):
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        id_file = tmp_path / "anonymous-id"
        id_file.write_text("existing-test-id-12345")

        anon_id = telemetry._get_anonymous_id()
        assert anon_id == "existing-test-id-12345"

    def test_returns_stable_id(self, tmp_path, monkeypatch):
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        id1 = telemetry._get_anonymous_id()
        # Reset the cached value but keep the file
        telemetry._anonymous_id = None
        id2 = telemetry._get_anonymous_id()
        assert id1 == id2

    def test_handles_unwritable_dir(self, monkeypatch):
        monkeypatch.setattr(
            telemetry,
            "_get_lucidshark_dir",
            lambda: Path("/nonexistent/deeply/nested/path"),
        )
        # Should not raise, just generate in-memory ID
        anon_id = telemetry._get_anonymous_id()
        assert len(anon_id) == 36


# ===================================================================
# _track_event (internal)
# ===================================================================


class TestTrackEvent:
    """Tests for internal event tracking."""

    def test_noop_when_disabled(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "0")
        telemetry._track_event("test_event", {"key": "value"})

    def test_never_raises(self, monkeypatch, tmp_path):
        """Telemetry must never crash the CLI."""
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        monkeypatch.setattr(
            telemetry, "_get_client", MagicMock(side_effect=RuntimeError("boom"))
        )
        telemetry._track_event("test_event")

    def test_calls_posthog_capture(self, mock_posthog):
        telemetry._track_event("test_event", {"custom": "prop"})

        mock_posthog.capture.assert_called_once()
        call_kwargs = mock_posthog.capture.call_args
        assert call_kwargs.kwargs["event"] == "test_event"
        assert call_kwargs.kwargs["properties"]["custom"] == "prop"
        assert "lucidshark_version" in call_kwargs.kwargs["properties"]
        assert "os" in call_kwargs.kwargs["properties"]

    def test_includes_base_properties(self, mock_posthog):
        telemetry._track_event("test_event")

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert "lucidshark_version" in props
        assert "os" in props
        assert "arch" in props
        assert "python_version" in props

    def test_noop_when_client_is_none(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        monkeypatch.setattr(telemetry, "_get_client", lambda: None)
        # Should not raise
        telemetry._track_event("test_event")


# ===================================================================
# _serialize_config
# ===================================================================


class TestSerializeConfig:
    """Tests for config serialization."""

    def test_serializes_dataclass(self):
        config = _FakeConfig(
            project=_FakeProjectConfig(name="myproj", languages=["python"])
        )
        result = telemetry._serialize_config(config)
        assert result["project"]["name"] == "myproj"
        assert result["project"]["languages"] == ["python"]

    def test_strips_config_sources(self):
        config = _FakeConfigWithPrivateFields(
            project=_FakeProjectConfig(languages=["go"]),
            _config_sources=["project:/some/path.yml"],
        )
        result = telemetry._serialize_config(config)
        assert "_config_sources" not in result
        assert result["project"]["languages"] == ["go"]

    def test_returns_empty_dict_on_non_dataclass(self):
        result = telemetry._serialize_config("not a dataclass")
        assert result == {}

    def test_returns_empty_dict_on_none(self):
        result = telemetry._serialize_config(None)
        assert result == {}

    def test_returns_empty_dict_on_unserializable(self):
        """Non-serializable objects should return {} without raising."""

        class BadConfig:
            pass

        result = telemetry._serialize_config(BadConfig())
        assert result == {}


# ===================================================================
# track_scan_completed
# ===================================================================


class TestTrackScanCompleted:
    """Tests for scan completion tracking."""

    def test_tracks_scan_with_all_properties(self, mock_posthog):
        config = _FakeConfig(
            project=_FakeProjectConfig(languages=["python", "typescript"])
        )
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(
                executed_domains=["linting", "sast"],
                scanners_used=[{"name": "ruff"}, {"name": "opengrep"}],
                duration_ms=5000,
                all_files=True,
            ),
            summary=_FakeScanSummary(
                total=42,
                ignored_total=3,
                by_severity={"high": 5, "low": 37},
                by_scanner={"linting": 30, "sast": 12},
            ),
            coverage_summary=_FakeCoverageSummary(
                coverage_percentage=85.5, passed=True
            ),
            duplication_summary=_FakeDuplicationSummary(
                duplication_percent=3.2, passed=True
            ),
        )

        telemetry.track_scan_completed(config=config, result=result, source="cli")

        mock_posthog.capture.assert_called_once()
        props = mock_posthog.capture.call_args.kwargs["properties"]

        assert props["source"] == "cli"
        assert props["executed_domains"] == ["linting", "sast"]
        assert props["domain_count"] == 2
        assert props["scanners_used"] == ["ruff", "opengrep"]
        assert props["duration_ms"] == 5000
        assert props["scan_mode"] == "full"
        assert props["total_issues"] == 42
        assert props["ignored_issues"] == 3
        assert props["issues_by_severity"] == {"high": 5, "low": 37}
        assert props["issues_by_domain"] == {"linting": 30, "sast": 12}
        assert props["coverage_percent"] == 85.5
        assert props["coverage_passed"] is True
        assert props["duplication_percent"] == 3.2
        assert props["duplication_passed"] is True
        # Config as single field
        assert "config" in props
        assert props["config"]["project"]["languages"] == ["python", "typescript"]
        # Base properties
        assert "lucidshark_version" in props
        assert "os" in props

    def test_optional_coverage_and_duplication(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(
                executed_domains=["linting"],
                duration_ms=100,
                all_files=False,
            ),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert "coverage_percent" not in props
        assert "coverage_passed" not in props
        assert "duplication_percent" not in props
        assert "duplication_passed" not in props
        assert props["scan_mode"] == "incremental"

    def test_tracks_scan_with_mcp_source(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(
                executed_domains=["linting"],
                scanners_used=[{"name": "ruff"}],
                duration_ms=1000,
            ),
            summary=_FakeScanSummary(total=5, by_severity={"low": 5}),
        )

        telemetry.track_scan_completed(config=config, result=result, source="mcp")

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["source"] == "mcp"

    def test_no_metadata(self, mock_posthog):
        """Result with metadata=None should still send event without metadata fields."""
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=None,
            summary=_FakeScanSummary(total=3),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert "executed_domains" not in props
        assert "duration_ms" not in props
        assert "scan_mode" not in props
        assert props["total_issues"] == 3

    def test_no_summary(self, mock_posthog):
        """Result with summary=None should still send event without summary fields."""
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["sca"], duration_ms=200),
            summary=None,
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["executed_domains"] == ["sca"]
        assert "total_issues" not in props
        assert "issues_by_severity" not in props

    def test_tool_skips_tracked(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["linting"]),
            summary=_FakeScanSummary(total=0),
            tool_skips=[_FakeToolSkip(), _FakeToolSkip()],
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["tool_skip_count"] == 2

    def test_no_tool_skips_omitted(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["linting"]),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert "tool_skip_count" not in props

    def test_scanners_with_empty_names_filtered(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(
                executed_domains=["linting"],
                scanners_used=[
                    {"name": "ruff"},
                    {"name": ""},
                    {},
                    {"name": "mypy"},
                ],
            ),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["scanners_used"] == ["ruff", "mypy"]

    def test_domains_are_sorted(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(
                executed_domains=["sast", "linting", "container"],
            ),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["executed_domains"] == ["container", "linting", "sast"]

    def test_noop_when_disabled(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "0")
        # Should not raise and should not try to access result fields
        telemetry.track_scan_completed(config=None, result=None)

    def test_never_raises_on_client_error(self, monkeypatch, tmp_path):
        """track_scan_completed must never crash the caller."""
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        monkeypatch.setattr(
            telemetry, "_get_client", MagicMock(side_effect=RuntimeError("boom"))
        )
        telemetry.track_scan_completed(config=None, result=None, source="cli")

    def test_never_raises_on_bad_result(self, mock_posthog):
        """Completely broken result/config should not crash."""
        telemetry.track_scan_completed(config="garbage", result=42, source="cli")

    def test_coverage_rounded(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["coverage"]),
            summary=_FakeScanSummary(total=0),
            coverage_summary=_FakeCoverageSummary(coverage_percentage=85.567),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["coverage_percent"] == 85.6

    def test_duplication_rounded(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["duplication"]),
            summary=_FakeScanSummary(total=0),
            duplication_summary=_FakeDuplicationSummary(duplication_percent=3.249),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["duplication_percent"] == 3.2

    def test_fires_exactly_one_event(self, mock_posthog):
        """A single scan should produce exactly one PostHog capture call."""
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["linting"]),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        assert mock_posthog.capture.call_count == 1

    def test_event_name_is_scan_completed(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["linting"]),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        assert mock_posthog.capture.call_args.kwargs["event"] == "scan_completed"

    def test_default_source_is_cli(self, mock_posthog):
        config = _FakeConfig()
        result = _FakeScanResult(
            metadata=_FakeScanMetadata(executed_domains=["linting"]),
            summary=_FakeScanSummary(total=0),
        )

        telemetry.track_scan_completed(config=config, result=result)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["source"] == "cli"


# ===================================================================
# track_init_completed
# ===================================================================


class TestTrackInitCompleted:
    """Tests for init completion tracking."""

    def test_tracks_success(self, mock_posthog):
        telemetry.track_init_completed(success=True)

        mock_posthog.capture.assert_called_once()
        call_kwargs = mock_posthog.capture.call_args
        assert call_kwargs.kwargs["event"] == "init_completed"
        assert call_kwargs.kwargs["properties"]["success"] is True

    def test_tracks_failure(self, mock_posthog):
        telemetry.track_init_completed(success=False)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["success"] is False

    def test_includes_base_properties(self, mock_posthog):
        telemetry.track_init_completed(success=True)

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert "lucidshark_version" in props
        assert "os" in props

    def test_noop_when_disabled(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "0")
        telemetry.track_init_completed(success=True)

    def test_never_raises(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        monkeypatch.setattr(
            telemetry, "_get_client", MagicMock(side_effect=RuntimeError("boom"))
        )
        telemetry.track_init_completed(success=True)


# ===================================================================
# track_autoconfigure_initiated
# ===================================================================


class TestTrackAutoconfigureInitiated:
    """Tests for autoconfigure initiation tracking."""

    def test_tracks_event(self, mock_posthog):
        telemetry.track_autoconfigure_initiated()

        mock_posthog.capture.assert_called_once()
        call_kwargs = mock_posthog.capture.call_args
        assert call_kwargs.kwargs["event"] == "autoconfigure_initiated"
        assert call_kwargs.kwargs["properties"]["source"] == "mcp"

    def test_includes_base_properties(self, mock_posthog):
        telemetry.track_autoconfigure_initiated()

        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert "lucidshark_version" in props
        assert "os" in props

    def test_noop_when_disabled(self, monkeypatch):
        monkeypatch.setenv("LUCIDSHARK_TELEMETRY", "0")
        telemetry.track_autoconfigure_initiated()

    def test_never_raises(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)
        monkeypatch.setattr(
            telemetry, "_get_client", MagicMock(side_effect=RuntimeError("boom"))
        )
        telemetry.track_autoconfigure_initiated()


# ===================================================================
# reset
# ===================================================================


class TestReset:
    """Tests for reset functionality."""

    def test_reset_clears_cached_state(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LUCIDSHARK_TELEMETRY", raising=False)
        monkeypatch.delenv("DO_NOT_TRACK", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setattr(telemetry, "_get_lucidshark_dir", lambda: tmp_path)

        # Prime caches
        telemetry.is_enabled()
        telemetry._get_anonymous_id()

        # Reset
        telemetry.reset()

        assert telemetry._enabled is None
        assert telemetry._anonymous_id is None
        assert telemetry._telemetry_client is None


# ===================================================================
# Integration: no old events remain
# ===================================================================


class TestNoLegacyEvents:
    """Verify the old command_executed / track_command API is gone."""

    def test_no_track_command_function(self):
        assert not hasattr(telemetry, "track_command")

    def test_no_public_track_event(self):
        """track_event is now private (_track_event)."""
        assert not hasattr(telemetry, "track_event")


# ===================================================================
# Integration: CLI scan _track_telemetry
# ===================================================================


class TestCLIScanTelemetryIntegration:
    """Verify CLI scan command calls telemetry correctly."""

    def test_track_telemetry_calls_track_scan_completed(self):
        """ScanCommand._track_telemetry passes config+result to track_scan_completed."""
        from lucidshark.cli.commands.scan import ScanCommand
        from lucidshark.core.models import ScanMetadata, ScanResult, ScanSummary

        cmd = ScanCommand(version="1.0.0")

        result = ScanResult(issues=[])
        result.summary = ScanSummary(
            total=7, by_severity={"low": 7}, by_scanner={"linting": 7}
        )
        result.metadata = ScanMetadata(
            lucidshark_version="1.0.0",
            scan_started_at="",
            scan_finished_at="",
            duration_ms=123,
            project_root="/tmp",
            executed_domains=["linting"],
            all_files=True,
        )

        from lucidshark.config.models import LucidSharkConfig

        config = LucidSharkConfig()

        with patch("lucidshark.telemetry.track_scan_completed") as mock_track:
            cmd._track_telemetry(config, result)
            mock_track.assert_called_once_with(
                config=config, result=result, source="cli"
            )

    def test_track_telemetry_never_raises(self):
        """_track_telemetry swallows all exceptions."""
        from lucidshark.cli.commands.scan import ScanCommand

        cmd = ScanCommand(version="1.0.0")

        with patch(
            "lucidshark.telemetry.track_scan_completed",
            side_effect=RuntimeError("boom"),
        ):
            # Should not raise
            cmd._track_telemetry(None, None)


# ===================================================================
# Integration: CLI init telemetry
# ===================================================================


class TestCLIInitTelemetryIntegration:
    """Verify CLI init command calls telemetry correctly."""

    def test_init_tracks_success(self, tmp_path):
        from argparse import Namespace
        from lucidshark.cli.commands.init import InitCommand

        cmd = InitCommand(version="1.0.0")
        args = Namespace(dry_run=True, force=False, remove=False)

        with patch("lucidshark.telemetry.track_init_completed") as mock_track:
            cmd.execute(args)
            mock_track.assert_called_once_with(success=True)


# ===================================================================
# Integration: CLI runner no longer fires command_executed
# ===================================================================


class TestCLIRunnerNoTrackCommand:
    """Verify the CLI runner no longer emits command_executed events."""

    def test_no_track_command_in_runner(self):
        """Runner source should not reference track_command at all."""
        import inspect
        from lucidshark.cli.runner import CLIRunner

        source = inspect.getsource(CLIRunner)
        assert "track_command" not in source


# ===================================================================
# Integration: MCP server no longer fires command_executed
# ===================================================================


class TestMCPServerNoTrackCommand:
    """Verify the MCP server no longer emits command_executed events."""

    def test_no_track_command_in_server(self):
        import inspect
        import lucidshark.mcp.server as server_mod

        source = inspect.getsource(server_mod)
        assert "track_command" not in source
        assert "_track_mcp_scan_telemetry" not in source


# ===================================================================
# Integration: DomainRunner.run_security tools_executed tracking
# ===================================================================


class TestDomainRunnerSecurityToolsExecuted:
    """Verify run_security appends to context.tools_executed."""

    def test_run_security_tracks_tool(self, tmp_path):
        from lucidshark.config.models import LucidSharkConfig
        from lucidshark.core.domain_runner import DomainRunner
        from lucidshark.core.models import ScanContext, ScanDomain

        config = LucidSharkConfig()
        runner = DomainRunner(tmp_path, config)

        context = ScanContext(
            project_root=tmp_path,
            paths=[],
            enabled_domains=[ScanDomain.SCA],
        )

        mock_scanner = MagicMock()
        mock_scanner.domains = [ScanDomain.SCA]
        mock_scanner.scan.return_value = []

        with (
            patch(
                "lucidshark.plugins.scanners.discover_scanner_plugins",
                return_value={"trivy": lambda **k: mock_scanner},
            ),
            patch(
                "lucidshark.core.domain_runner.filter_scanners_by_config",
                return_value={"trivy": lambda **k: mock_scanner},
            ),
        ):
            runner.run_security(context, ScanDomain.SCA)

        assert len(context.tools_executed) == 1
        assert context.tools_executed[0]["name"] == "trivy"
        assert context.tools_executed[0]["domains"] == ["sca"]
        assert context.tools_executed[0]["success"] is True
        assert context.tools_executed[0]["error"] is None

    def test_run_security_no_tracking_on_wrong_domain(self, tmp_path):
        from lucidshark.config.models import LucidSharkConfig
        from lucidshark.core.domain_runner import DomainRunner
        from lucidshark.core.models import ScanContext, ScanDomain

        config = LucidSharkConfig()
        runner = DomainRunner(tmp_path, config)

        context = ScanContext(
            project_root=tmp_path,
            paths=[],
            enabled_domains=[ScanDomain.SAST],
        )

        mock_scanner = MagicMock()
        mock_scanner.domains = [ScanDomain.SCA]  # Wrong domain
        mock_scanner.scan.return_value = []

        with (
            patch(
                "lucidshark.plugins.scanners.discover_scanner_plugins",
                return_value={"trivy": lambda **k: mock_scanner},
            ),
            patch(
                "lucidshark.core.domain_runner.filter_scanners_by_config",
                return_value={"trivy": lambda **k: mock_scanner},
            ),
        ):
            runner.run_security(context, ScanDomain.SAST)

        assert len(context.tools_executed) == 0

    def test_run_security_no_tracking_on_exception(self, tmp_path):
        from lucidshark.config.models import LucidSharkConfig
        from lucidshark.core.domain_runner import DomainRunner
        from lucidshark.core.models import ScanContext, ScanDomain

        config = LucidSharkConfig()
        runner = DomainRunner(tmp_path, config)

        context = ScanContext(
            project_root=tmp_path,
            paths=[],
            enabled_domains=[ScanDomain.SCA],
        )

        mock_scanner = MagicMock()
        mock_scanner.domains = [ScanDomain.SCA]
        mock_scanner.scan.side_effect = RuntimeError("scanner crashed")

        with (
            patch(
                "lucidshark.plugins.scanners.discover_scanner_plugins",
                return_value={"trivy": lambda **k: mock_scanner},
            ),
            patch(
                "lucidshark.core.domain_runner.filter_scanners_by_config",
                return_value={"trivy": lambda **k: mock_scanner},
            ),
        ):
            runner.run_security(context, ScanDomain.SCA)

        assert len(context.tools_executed) == 0


# ===================================================================
# Integration: using real ScanResult/LucidSharkConfig
# ===================================================================


class TestTrackScanCompletedWithRealModels:
    """Test track_scan_completed with actual model classes, not fakes."""

    def test_with_real_scan_result(self, mock_posthog):
        from lucidshark.config.models import LucidSharkConfig
        from lucidshark.core.models import ScanMetadata, ScanResult, ScanSummary

        config = LucidSharkConfig()

        result = ScanResult(issues=[])
        result.summary = ScanSummary(
            total=10,
            ignored_total=2,
            by_severity={"high": 3, "medium": 7},
            by_scanner={"linting": 10},
        )
        result.metadata = ScanMetadata(
            lucidshark_version="0.7.0",
            scan_started_at="2025-01-01T00:00:00",
            scan_finished_at="2025-01-01T00:00:05",
            duration_ms=5000,
            project_root="/tmp/project",
            executed_domains=["linting", "sca"],
            scanners_used=[{"name": "ruff"}, {"name": "trivy"}],
            all_files=False,
            total_issues=10,
        )

        telemetry.track_scan_completed(config=config, result=result, source="cli")

        mock_posthog.capture.assert_called_once()
        props = mock_posthog.capture.call_args.kwargs["properties"]

        assert props["source"] == "cli"
        assert props["executed_domains"] == ["linting", "sca"]
        assert props["scanners_used"] == ["ruff", "trivy"]
        assert props["total_issues"] == 10
        assert props["ignored_issues"] == 2
        assert props["scan_mode"] == "incremental"
        assert props["duration_ms"] == 5000
        # Config is serialized as a dict with real model structure
        assert isinstance(props["config"], dict)
        assert "project" in props["config"]
        assert "_config_sources" not in props["config"]

    def test_with_real_scan_result_minimal(self, mock_posthog):
        """Minimal ScanResult with no metadata or summary."""
        from lucidshark.config.models import LucidSharkConfig
        from lucidshark.core.models import ScanResult

        config = LucidSharkConfig()
        result = ScanResult(issues=[])

        telemetry.track_scan_completed(config=config, result=result)

        mock_posthog.capture.assert_called_once()
        props = mock_posthog.capture.call_args.kwargs["properties"]
        assert props["source"] == "cli"
        assert isinstance(props["config"], dict)
        # No metadata/summary fields should be present
        assert "executed_domains" not in props
        assert "total_issues" not in props
