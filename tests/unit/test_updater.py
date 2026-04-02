"""Tests for lucidshark.updater — background auto-update system."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from lucidshark.updater import (
    CHECK_INTERVAL_SECONDS,
    MIN_BINARY_SIZE,
    PENDING_UPDATE_DIR,
    PENDING_VERSION_FILE,
    UPDATE_CHECK_FILE,
    _cleanup_pending,
    _is_newer,
    _parse_version,
    _write_check_cache,
    apply_pending_update,
    background_update_check,
    check_for_update,
    download_pending_update,
    get_self_binary_path,
    should_check_for_update,
    start_background_update_check,
)


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------


class TestParseVersion:
    """Tests for _parse_version helper."""

    def test_simple_version(self) -> None:
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_strips_v_prefix(self) -> None:
        assert _parse_version("v1.2.3") == (1, 2, 3)

    def test_two_components(self) -> None:
        assert _parse_version("1.2") == (1, 2)

    def test_single_component(self) -> None:
        assert _parse_version("5") == (5,)

    def test_non_numeric_part_becomes_zero(self) -> None:
        assert _parse_version("1.beta.3") == (1, 0, 3)

    def test_empty_string(self) -> None:
        assert _parse_version("") == (0,)


# ---------------------------------------------------------------------------
# _is_newer
# ---------------------------------------------------------------------------


class TestIsNewer:
    """Tests for _is_newer helper."""

    def test_newer_patch(self) -> None:
        assert _is_newer("0.7.1", "0.7.0") is True

    def test_newer_minor(self) -> None:
        assert _is_newer("0.8.0", "0.7.0") is True

    def test_newer_major(self) -> None:
        assert _is_newer("1.0.0", "0.7.0") is True

    def test_same_version(self) -> None:
        assert _is_newer("0.7.0", "0.7.0") is False

    def test_older_version(self) -> None:
        assert _is_newer("0.6.0", "0.7.0") is False

    def test_handles_v_prefix(self) -> None:
        assert _is_newer("v0.8.0", "0.7.0") is True

    def test_handles_v_prefix_on_both(self) -> None:
        assert _is_newer("v0.8.0", "v0.7.0") is True

    def test_different_length_versions(self) -> None:
        # (0, 8) > (0, 7, 0) because tuple comparison is left-to-right
        assert _is_newer("0.8", "0.7.0") is True


# ---------------------------------------------------------------------------
# get_self_binary_path
# ---------------------------------------------------------------------------


class TestGetSelfBinaryPath:
    """Tests for get_self_binary_path."""

    def test_returns_none_when_not_frozen(self) -> None:
        # Default dev mode — sys.frozen is not set
        with patch.object(sys, "frozen", False, create=True):
            assert get_self_binary_path() is None

    def test_returns_none_when_frozen_attr_missing(self) -> None:
        # Ensure frozen attribute doesn't exist
        if hasattr(sys, "frozen"):
            with patch.object(sys, "frozen", False):
                assert get_self_binary_path() is None
        else:
            assert get_self_binary_path() is None

    def test_returns_path_when_frozen(self, tmp_path: Path) -> None:
        binary = tmp_path / "lucidshark"
        binary.write_bytes(b"\x00" * 100)
        with patch.object(sys, "frozen", True, create=True):
            with patch.object(sys, "executable", str(binary)):
                result = get_self_binary_path()
                assert result is not None
                assert result == binary.resolve()


# ---------------------------------------------------------------------------
# should_check_for_update
# ---------------------------------------------------------------------------


class TestShouldCheckForUpdate:
    """Tests for should_check_for_update."""

    def test_returns_true_when_no_cache_file(self, tmp_path: Path) -> None:
        assert should_check_for_update(tmp_path) is True

    def test_returns_true_when_cache_expired(self, tmp_path: Path) -> None:
        expired = datetime.now(timezone.utc) - timedelta(hours=25)
        cache_file = tmp_path / UPDATE_CHECK_FILE
        cache_file.write_text(json.dumps({"last_check_utc": expired.isoformat()}))
        assert should_check_for_update(tmp_path) is True

    def test_returns_false_when_cache_fresh(self, tmp_path: Path) -> None:
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        cache_file = tmp_path / UPDATE_CHECK_FILE
        cache_file.write_text(json.dumps({"last_check_utc": recent.isoformat()}))
        assert should_check_for_update(tmp_path) is False

    def test_returns_true_when_cache_exactly_at_threshold(self, tmp_path: Path) -> None:
        exact = datetime.now(timezone.utc) - timedelta(seconds=CHECK_INTERVAL_SECONDS)
        cache_file = tmp_path / UPDATE_CHECK_FILE
        cache_file.write_text(json.dumps({"last_check_utc": exact.isoformat()}))
        assert should_check_for_update(tmp_path) is True

    def test_returns_true_when_cache_file_corrupt(self, tmp_path: Path) -> None:
        cache_file = tmp_path / UPDATE_CHECK_FILE
        cache_file.write_text("not valid json")
        assert should_check_for_update(tmp_path) is True

    def test_returns_true_when_cache_missing_timestamp(self, tmp_path: Path) -> None:
        cache_file = tmp_path / UPDATE_CHECK_FILE
        cache_file.write_text(json.dumps({"latest_version": "0.8.0"}))
        assert should_check_for_update(tmp_path) is True


# ---------------------------------------------------------------------------
# _write_check_cache
# ---------------------------------------------------------------------------


class TestWriteCheckCache:
    """Tests for _write_check_cache."""

    def test_writes_cache_file(self, tmp_path: Path) -> None:
        _write_check_cache(tmp_path, "2026-04-02T12:00:00+00:00", "0.8.0", "0.7.0")
        cache_file = tmp_path / UPDATE_CHECK_FILE
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert data["last_check_utc"] == "2026-04-02T12:00:00+00:00"
        assert data["latest_version"] == "0.8.0"
        assert data["current_version_at_check"] == "0.7.0"

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "cache"
        _write_check_cache(nested, "2026-04-02T12:00:00+00:00", "0.8.0", "0.7.0")
        assert (nested / UPDATE_CHECK_FILE).exists()

    def test_overwrites_existing_cache(self, tmp_path: Path) -> None:
        _write_check_cache(tmp_path, "2026-04-01T00:00:00+00:00", "0.7.0", "0.7.0")
        _write_check_cache(tmp_path, "2026-04-02T00:00:00+00:00", "0.8.0", "0.7.0")
        data = json.loads((tmp_path / UPDATE_CHECK_FILE).read_text())
        assert data["latest_version"] == "0.8.0"


# ---------------------------------------------------------------------------
# check_for_update
# ---------------------------------------------------------------------------


class TestCheckForUpdate:
    """Tests for check_for_update."""

    def _mock_github_response(self, tag_name: str) -> MagicMock:
        """Create a mock response from the GitHub API."""
        body = json.dumps({"tag_name": tag_name}).encode("utf-8")
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_returns_info_when_newer_available(self, tmp_path: Path) -> None:
        resp = self._mock_github_response("v0.8.0")
        with patch("lucidshark.bootstrap.download.secure_urlopen", return_value=resp):  # noqa: E501
            with patch(
                "lucidshark.bootstrap.platform.get_platform_info",
                return_value=MagicMock(bundle_name="darwin-arm64"),
            ):
                result = check_for_update(tmp_path, "0.7.0")
        assert result is not None
        assert result["version"] == "0.8.0"
        assert "darwin-arm64" in result["download_url"]
        assert result["tag"] == "v0.8.0"

    def test_returns_none_when_up_to_date(self, tmp_path: Path) -> None:
        resp = self._mock_github_response("v0.7.0")
        with patch("lucidshark.bootstrap.download.secure_urlopen", return_value=resp):  # noqa: E501
            with patch(
                "lucidshark.bootstrap.platform.get_platform_info",
                return_value=MagicMock(bundle_name="darwin-arm64"),
            ):
                result = check_for_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_when_current_is_newer(self, tmp_path: Path) -> None:
        resp = self._mock_github_response("v0.6.0")
        with patch("lucidshark.bootstrap.download.secure_urlopen", return_value=resp):  # noqa: E501
            with patch(
                "lucidshark.bootstrap.platform.get_platform_info",
                return_value=MagicMock(bundle_name="darwin-arm64"),
            ):
                result = check_for_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_on_network_error(self, tmp_path: Path) -> None:
        with patch(
            "lucidshark.bootstrap.download.secure_urlopen",
            side_effect=OSError("timeout"),
        ):
            with patch(
                "lucidshark.bootstrap.platform.get_platform_info",
                return_value=MagicMock(bundle_name="darwin-arm64"),
            ):
                result = check_for_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_on_unsupported_platform(self, tmp_path: Path) -> None:
        with patch(
            "lucidshark.bootstrap.platform.get_platform_info",
            side_effect=ValueError("Unsupported"),
        ):
            result = check_for_update(tmp_path, "0.7.0")
        assert result is None

    def test_writes_cache_even_when_up_to_date(self, tmp_path: Path) -> None:
        resp = self._mock_github_response("v0.7.0")
        with patch("lucidshark.bootstrap.download.secure_urlopen", return_value=resp):  # noqa: E501
            with patch(
                "lucidshark.bootstrap.platform.get_platform_info",
                return_value=MagicMock(bundle_name="linux-amd64"),
            ):
                check_for_update(tmp_path, "0.7.0")
        cache_file = tmp_path / UPDATE_CHECK_FILE
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert data["latest_version"] == "0.7.0"

    def test_constructs_correct_download_url(self, tmp_path: Path) -> None:
        resp = self._mock_github_response("v1.0.0")
        with patch("lucidshark.bootstrap.download.secure_urlopen", return_value=resp):  # noqa: E501
            with patch(
                "lucidshark.bootstrap.platform.get_platform_info",
                return_value=MagicMock(bundle_name="linux-amd64"),
            ):
                result = check_for_update(tmp_path, "0.7.0")
        assert result is not None
        assert result["download_url"] == (
            "https://github.com/toniantunovi/lucidshark/releases/download/"
            "v1.0.0/lucidshark-linux-amd64"
        )


# ---------------------------------------------------------------------------
# download_pending_update
# ---------------------------------------------------------------------------


class TestDownloadPendingUpdate:
    """Tests for download_pending_update."""

    def test_successful_download(self, tmp_path: Path) -> None:
        def fake_download(_url: str, dest: Path, timeout: float = 60.0) -> None:
            dest.write_bytes(b"\x00" * (MIN_BINARY_SIZE + 1))

        with patch(
            "lucidshark.bootstrap.download.download_file", side_effect=fake_download
        ):
            result = download_pending_update(
                tmp_path, "https://example.com/lucidshark", "0.8.0"
            )
        assert result is True
        pending_binary = tmp_path / PENDING_UPDATE_DIR / "lucidshark"
        assert pending_binary.exists()
        assert os.access(pending_binary, os.X_OK)

        version_file = tmp_path / PENDING_UPDATE_DIR / PENDING_VERSION_FILE
        assert version_file.exists()
        meta = json.loads(version_file.read_text())
        assert meta["version"] == "0.8.0"
        assert meta["url"] == "https://example.com/lucidshark"

    def test_rejects_too_small_download(self, tmp_path: Path) -> None:
        def fake_download(_url: str, dest: Path, timeout: float = 60.0) -> None:
            dest.write_bytes(b"\x00" * 100)  # Way too small

        with patch(
            "lucidshark.bootstrap.download.download_file", side_effect=fake_download
        ):
            result = download_pending_update(
                tmp_path, "https://example.com/lucidshark", "0.8.0"
            )
        assert result is False
        assert not (tmp_path / PENDING_UPDATE_DIR / "lucidshark").exists()

    def test_returns_false_on_download_error(self, tmp_path: Path) -> None:
        with patch(
            "lucidshark.bootstrap.download.download_file",
            side_effect=OSError("network error"),
        ):
            result = download_pending_update(
                tmp_path, "https://example.com/lucidshark", "0.8.0"
            )
        assert result is False

    def test_cleans_up_on_failure(self, tmp_path: Path) -> None:
        with patch(
            "lucidshark.bootstrap.download.download_file",
            side_effect=OSError("network error"),
        ):
            download_pending_update(tmp_path, "https://example.com/lucidshark", "0.8.0")
        pending_dir = tmp_path / PENDING_UPDATE_DIR
        assert not pending_dir.exists()


# ---------------------------------------------------------------------------
# _cleanup_pending
# ---------------------------------------------------------------------------


class TestCleanupPending:
    """Tests for _cleanup_pending."""

    def test_removes_pending_directory(self, tmp_path: Path) -> None:
        pending = tmp_path / "pending-update"
        pending.mkdir()
        (pending / "lucidshark").write_bytes(b"\x00" * 10)
        (pending / "version.json").write_text('{"version": "0.8.0"}')
        _cleanup_pending(pending)
        assert not pending.exists()

    def test_does_not_raise_if_dir_missing(self, tmp_path: Path) -> None:
        pending = tmp_path / "nonexistent"
        _cleanup_pending(pending)  # Should not raise


# ---------------------------------------------------------------------------
# apply_pending_update
# ---------------------------------------------------------------------------


class TestApplyPendingUpdate:
    """Tests for apply_pending_update (Phase B)."""

    def _stage_pending_update(
        self,
        cache_dir: Path,
        version: str = "0.8.0",
        binary_size: int = MIN_BINARY_SIZE + 1,
        executable: bool = True,
    ) -> Path:
        """Create a staged pending update in cache_dir."""
        pending_dir = cache_dir / PENDING_UPDATE_DIR
        pending_dir.mkdir(parents=True, exist_ok=True)

        binary = pending_dir / "lucidshark"
        binary.write_bytes(b"\x00" * binary_size)
        if executable:
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

        version_file = pending_dir / PENDING_VERSION_FILE
        version_file.write_text(json.dumps({"version": version}))
        return pending_dir

    def test_returns_none_when_no_pending_update(self, tmp_path: Path) -> None:
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_when_binary_missing(self, tmp_path: Path) -> None:
        pending_dir = tmp_path / PENDING_UPDATE_DIR
        pending_dir.mkdir(parents=True)
        (pending_dir / PENDING_VERSION_FILE).write_text('{"version": "0.8.0"}')
        # No binary file
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_when_version_file_missing(self, tmp_path: Path) -> None:
        pending_dir = tmp_path / PENDING_UPDATE_DIR
        pending_dir.mkdir(parents=True)
        binary = pending_dir / "lucidshark"
        binary.write_bytes(b"\x00" * (MIN_BINARY_SIZE + 1))
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        # No version.json
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_when_version_not_newer(self, tmp_path: Path) -> None:
        self._stage_pending_update(tmp_path, version="0.7.0")
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_cleans_up_when_version_not_newer(self, tmp_path: Path) -> None:
        self._stage_pending_update(tmp_path, version="0.6.0")
        apply_pending_update(tmp_path, "0.7.0")
        assert not (tmp_path / PENDING_UPDATE_DIR).exists()

    def test_returns_none_when_binary_too_small(self, tmp_path: Path) -> None:
        self._stage_pending_update(tmp_path, binary_size=100)
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_cleans_up_when_binary_too_small(self, tmp_path: Path) -> None:
        self._stage_pending_update(tmp_path, binary_size=100)
        apply_pending_update(tmp_path, "0.7.0")
        assert not (tmp_path / PENDING_UPDATE_DIR).exists()

    def test_returns_none_when_binary_not_executable(self, tmp_path: Path) -> None:
        self._stage_pending_update(tmp_path, executable=False)
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_when_not_frozen(self, tmp_path: Path) -> None:
        self._stage_pending_update(tmp_path)
        # get_self_binary_path returns None when not frozen
        with patch("lucidshark.updater.get_self_binary_path", return_value=None):
            result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None

    def test_returns_none_when_version_json_corrupt(self, tmp_path: Path) -> None:
        pending_dir = tmp_path / PENDING_UPDATE_DIR
        pending_dir.mkdir(parents=True)
        (pending_dir / "lucidshark").write_bytes(b"\x00" * (MIN_BINARY_SIZE + 1))
        (pending_dir / PENDING_VERSION_FILE).write_text("not json")
        result = apply_pending_update(tmp_path, "0.7.0")
        assert result is None
        # Corrupt pending should be cleaned up
        assert not pending_dir.exists()

    def test_successful_apply_swaps_binary(self, tmp_path: Path) -> None:
        """Test the full apply flow with a mock binary path."""
        # Set up the "installed" binary
        install_dir = tmp_path / "bin"
        install_dir.mkdir()
        installed_binary = install_dir / "lucidshark"
        installed_binary.write_bytes(b"OLD_BINARY")

        # Set up the pending update
        cache_dir = tmp_path / "cache"
        self._stage_pending_update(cache_dir, version="0.8.0")

        with patch(
            "lucidshark.updater.get_self_binary_path",
            return_value=installed_binary,
        ):
            result = apply_pending_update(cache_dir, "0.7.0")

        assert result == "0.8.0"
        # Binary was replaced
        assert installed_binary.exists()
        assert installed_binary.read_bytes() != b"OLD_BINARY"
        # Pending dir was cleaned up
        assert not (cache_dir / PENDING_UPDATE_DIR).exists()

    def test_apply_cleans_up_staging_on_rename_failure(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "bin"
        install_dir.mkdir()
        installed_binary = install_dir / "lucidshark"
        installed_binary.write_bytes(b"OLD_BINARY")

        cache_dir = tmp_path / "cache"
        self._stage_pending_update(cache_dir, version="0.8.0")

        with patch(
            "lucidshark.updater.get_self_binary_path",
            return_value=installed_binary,
        ):
            with patch("os.rename", side_effect=OSError("permission denied")):
                result = apply_pending_update(cache_dir, "0.7.0")

        assert result is None
        # Original binary unchanged
        assert installed_binary.read_bytes() == b"OLD_BINARY"


# ---------------------------------------------------------------------------
# background_update_check
# ---------------------------------------------------------------------------


class TestBackgroundUpdateCheck:
    """Tests for background_update_check orchestration."""

    def test_skips_when_check_not_due(self, tmp_path: Path) -> None:
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        cache_file = tmp_path / UPDATE_CHECK_FILE
        cache_file.write_text(json.dumps({"last_check_utc": recent.isoformat()}))

        with patch("lucidshark.updater.check_for_update") as mock_check:
            background_update_check(tmp_path, "0.7.0")
        mock_check.assert_not_called()

    def test_calls_check_when_due(self, tmp_path: Path) -> None:
        with patch(
            "lucidshark.updater.check_for_update", return_value=None
        ) as mock_check:
            background_update_check(tmp_path, "0.7.0")
        mock_check.assert_called_once_with(tmp_path, "0.7.0")

    def test_downloads_when_update_available(self, tmp_path: Path) -> None:
        update_info = {
            "version": "0.8.0",
            "download_url": "https://example.com/lucidshark",
            "tag": "v0.8.0",
        }
        with patch("lucidshark.updater.check_for_update", return_value=update_info):
            with patch("lucidshark.updater.download_pending_update") as mock_download:
                background_update_check(tmp_path, "0.7.0")
        mock_download.assert_called_once_with(
            tmp_path, "https://example.com/lucidshark", "0.8.0"
        )

    def test_skips_download_if_already_staged(self, tmp_path: Path) -> None:
        # Stage an existing pending update for the same version
        pending_dir = tmp_path / PENDING_UPDATE_DIR
        pending_dir.mkdir(parents=True)
        (pending_dir / PENDING_VERSION_FILE).write_text(
            json.dumps({"version": "0.8.0"})
        )

        update_info = {
            "version": "0.8.0",
            "download_url": "https://example.com/lucidshark",
            "tag": "v0.8.0",
        }
        with patch("lucidshark.updater.check_for_update", return_value=update_info):
            with patch("lucidshark.updater.download_pending_update") as mock_download:
                background_update_check(tmp_path, "0.7.0")
        mock_download.assert_not_called()

    def test_downloads_if_staged_version_is_different(self, tmp_path: Path) -> None:
        pending_dir = tmp_path / PENDING_UPDATE_DIR
        pending_dir.mkdir(parents=True)
        (pending_dir / PENDING_VERSION_FILE).write_text(
            json.dumps({"version": "0.7.5"})
        )

        update_info = {
            "version": "0.8.0",
            "download_url": "https://example.com/lucidshark",
            "tag": "v0.8.0",
        }
        with patch("lucidshark.updater.check_for_update", return_value=update_info):
            with patch("lucidshark.updater.download_pending_update") as mock_download:
                background_update_check(tmp_path, "0.7.0")
        mock_download.assert_called_once()

    def test_never_raises(self, tmp_path: Path) -> None:
        """background_update_check must swallow all exceptions."""
        with patch(
            "lucidshark.updater.should_check_for_update",
            side_effect=RuntimeError("unexpected"),
        ):
            # Should not raise
            background_update_check(tmp_path, "0.7.0")


# ---------------------------------------------------------------------------
# start_background_update_check
# ---------------------------------------------------------------------------


class TestStartBackgroundUpdateCheck:
    """Tests for start_background_update_check."""

    def test_spawns_daemon_thread(self, tmp_path: Path) -> None:
        with patch("lucidshark.updater.background_update_check") as mock_check:
            start_background_update_check(tmp_path, "0.7.0")
            # Find the thread by name
            threads = [
                t for t in threading.enumerate() if t.name == "lucidshark-update-check"
            ]
            # Wait for it to finish so we can assert
            for t in threads:
                t.join(timeout=5)
        mock_check.assert_called_once_with(tmp_path, "0.7.0")

    def test_thread_is_daemon(self, tmp_path: Path) -> None:
        original_init = threading.Thread.__init__

        daemon_flags: list[bool] = []

        def capture_init(self_thread: Any, *args: Any, **kwargs: Any) -> None:
            original_init(self_thread, *args, **kwargs)
            if kwargs.get("name") == "lucidshark-update-check":
                daemon_flags.append(self_thread.daemon)

        with patch("lucidshark.updater.background_update_check"):
            with patch.object(threading.Thread, "__init__", capture_init):
                start_background_update_check(tmp_path, "0.7.0")

        assert len(daemon_flags) == 1
        assert daemon_flags[0] is True
