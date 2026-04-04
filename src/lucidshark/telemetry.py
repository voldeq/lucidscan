"""Anonymous, opt-out telemetry for LucidShark.

Collects anonymous usage data to help improve the product. All data is
anonymous — no PII, no source code, no file paths, no IP addresses are stored.

Exactly three events are emitted:
  - scan_completed    — after every scan (CLI + MCP), with config and results
  - init_completed    — after ``lucidshark init`` (CLI only)
  - autoconfigure_initiated — when autoconfigure is triggered (MCP only)

No other events are sent. See ``lucidshark help`` for full details.

Opt out by setting the environment variable:
    export LUCIDSHARK_TELEMETRY=0

Or by creating a file at ~/.lucidshark/telemetry-optout
"""

from __future__ import annotations

import atexit
import logging
import os
import platform
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

LOGGER = logging.getLogger(__name__)

# PostHog project API key (public, safe to embed - this is a write-only key)
_POSTHOG_API_KEY = "phc_jQ0TDwA4tX7DkP5Rf1Pmr6mu9mPgtNmYh2QYkFjNmWP"
_POSTHOG_HOST = "https://us.i.posthog.com"

_telemetry_client: Optional[Any] = None
_anonymous_id: Optional[str] = None
_enabled: Optional[bool] = None


def _get_lucidshark_dir() -> Path:
    """Get the ~/.lucidshark directory path."""
    return Path.home() / ".lucidshark"


def is_enabled() -> bool:
    """Check if telemetry is enabled.

    Telemetry is enabled by default. It can be disabled by:
    1. Setting LUCIDSHARK_TELEMETRY=0 (or "false", "no", "off")
    2. Setting DO_NOT_TRACK=1 (standard env var)
    3. Creating ~/.lucidshark/telemetry-optout file
    4. Running in CI (CI=true env var) - CI environments are excluded

    Returns:
        True if telemetry should be collected.
    """
    global _enabled
    if _enabled is not None:
        return _enabled

    # Check LUCIDSHARK_TELEMETRY env var
    telemetry_env = os.environ.get("LUCIDSHARK_TELEMETRY", "").lower().strip()
    if telemetry_env in ("0", "false", "no", "off"):
        _enabled = False
        return False

    # Check DO_NOT_TRACK standard env var
    if os.environ.get("DO_NOT_TRACK", "").strip() == "1":
        _enabled = False
        return False

    # Check CI env var - don't collect from CI runs
    ci_env = os.environ.get("CI", "").lower().strip()
    if ci_env in ("true", "1"):
        _enabled = False
        return False

    # Check opt-out file
    optout_file = _get_lucidshark_dir() / "telemetry-optout"
    if optout_file.exists():
        _enabled = False
        return False

    _enabled = True
    return True


def _get_anonymous_id() -> str:
    """Get or create a stable anonymous identifier.

    Stores a random UUID in ~/.lucidshark/anonymous-id. This ID has no
    connection to the user's identity - it's purely for counting unique
    installations.

    Returns:
        Anonymous UUID string.
    """
    global _anonymous_id
    if _anonymous_id is not None:
        return _anonymous_id

    id_file = _get_lucidshark_dir() / "anonymous-id"

    try:
        if id_file.exists():
            stored_id = id_file.read_text().strip()
            if stored_id:
                _anonymous_id = stored_id
                return stored_id
    except OSError:
        pass

    # Generate new ID
    new_id = str(uuid.uuid4())

    try:
        id_file.parent.mkdir(parents=True, exist_ok=True)
        id_file.write_text(new_id)
    except OSError:
        pass

    _anonymous_id = new_id
    return new_id


def _get_client() -> Optional[Any]:
    """Get or initialize the PostHog client.

    Returns:
        PostHog client instance, or None if unavailable.
    """
    global _telemetry_client

    if _telemetry_client is not None:
        return _telemetry_client

    try:
        from posthog import Posthog

        client = Posthog(
            api_key=_POSTHOG_API_KEY,
            host=_POSTHOG_HOST,
            sync_mode=False,
        )
        # Disable PostHog's own logging to avoid noise
        client.log = logging.getLogger("posthog")
        client.log.setLevel(logging.CRITICAL)

        # Register shutdown handler to flush events
        atexit.register(_shutdown)

        _telemetry_client = client
        return client
    except Exception:
        LOGGER.debug("PostHog client not available, telemetry disabled")
        return None


def _shutdown() -> None:
    """Flush and shut down the telemetry client."""
    global _telemetry_client
    if _telemetry_client is not None:
        try:
            _telemetry_client.flush()
            _telemetry_client.shutdown()
        except Exception:
            pass
        _telemetry_client = None


def _get_base_properties() -> Dict[str, Any]:
    """Get base properties included with every event.

    Returns:
        Dictionary of anonymous system properties.
    """
    from lucidshark import __version__

    return {
        "lucidshark_version": __version__,
        "os": platform.system().lower(),
        "os_version": platform.release(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
    }


def _track_event(event_name: str, properties: Optional[Dict[str, Any]] = None) -> None:
    """Track an anonymous telemetry event.

    This is fire-and-forget - it never raises exceptions or blocks the CLI.

    Args:
        event_name: Name of the event.
        properties: Optional event properties.
    """
    if not is_enabled():
        return

    try:
        client = _get_client()
        if client is None:
            return

        all_properties = _get_base_properties()
        if properties:
            all_properties.update(properties)

        client.capture(
            distinct_id=_get_anonymous_id(),
            event=event_name,
            properties=all_properties,
        )
    except Exception:
        # Never let telemetry crash the CLI
        LOGGER.debug("Failed to send telemetry event", exc_info=True)


def _serialize_config(config: Any) -> Dict[str, Any]:
    """Serialize LucidSharkConfig to a telemetry-safe dict.

    Strips private fields and file paths. Returns a clean dict
    representing the effective configuration.
    """
    try:
        d = asdict(config)
        d.pop("_config_sources", None)
        return d
    except Exception:
        return {}


def track_scan_completed(
    config: Any,
    result: Any,
    source: str = "cli",
) -> None:
    """Track a completed scan with config and result data.

    Config is sent as a single field. Result fields are extracted from the
    same ScanResult object that reporters use, ensuring consistency.

    Never raises or blocks.

    Args:
        config: LucidSharkConfig instance.
        result: ScanResult instance (same object reporters receive).
        source: "cli" or "mcp".
    """
    try:
        properties: Dict[str, Any] = {
            "source": source,
            "config": _serialize_config(config),
        }

        # From metadata (same as JSON reporter uses via asdict(result.metadata))
        if result.metadata:
            properties["executed_domains"] = sorted(result.metadata.executed_domains)
            properties["domain_count"] = len(result.metadata.executed_domains)
            properties["scanners_used"] = [
                s.get("name", "") for s in result.metadata.scanners_used if s.get("name")
            ]
            properties["duration_ms"] = result.metadata.duration_ms
            properties["scan_mode"] = "full" if result.metadata.all_files else "incremental"

        # From summary (same as JSON reporter uses via asdict(result.summary))
        if result.summary:
            properties["total_issues"] = result.summary.total
            properties["ignored_issues"] = result.summary.ignored_total
            properties["issues_by_severity"] = result.summary.by_severity
            properties["issues_by_domain"] = result.summary.by_scanner

        # From coverage summary (same as JSON reporter)
        if result.coverage_summary:
            properties["coverage_percent"] = round(
                result.coverage_summary.coverage_percentage, 1
            )
            properties["coverage_passed"] = result.coverage_summary.passed

        # From duplication summary (same as JSON reporter)
        if result.duplication_summary:
            properties["duplication_percent"] = round(
                result.duplication_summary.duplication_percent, 1
            )
            properties["duplication_passed"] = result.duplication_summary.passed

        # Tool skips
        if result.tool_skips:
            properties["tool_skip_count"] = len(result.tool_skips)

        _track_event("scan_completed", properties)
    except Exception:
        pass


def track_init_completed(success: bool) -> None:
    """Track a completed init command.

    Never raises or blocks.

    Args:
        success: Whether init completed successfully.
    """
    try:
        _track_event("init_completed", {"success": success})
    except Exception:
        pass


def track_autoconfigure_initiated() -> None:
    """Track that autoconfigure was initiated via MCP.

    Never raises or blocks.
    """
    try:
        _track_event("autoconfigure_initiated", {"source": "mcp"})
    except Exception:
        pass


def reset() -> None:
    """Reset telemetry state. Used for testing."""
    global _telemetry_client, _anonymous_id, _enabled
    _shutdown()
    _telemetry_client = None
    _anonymous_id = None
    _enabled = None
