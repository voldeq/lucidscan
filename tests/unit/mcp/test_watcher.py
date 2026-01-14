"""Unit tests for MCP file watcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from lucidscan.config import LucidScanConfig
from lucidscan.mcp.watcher import LucidScanFileWatcher


class TestLucidScanFileWatcher:
    """Tests for LucidScanFileWatcher."""

    @pytest.fixture
    def project_root(self, tmp_path: Path) -> Path:
        """Create a temporary project root."""
        return tmp_path

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test configuration."""
        return LucidScanConfig()

    @pytest.fixture
    def watcher(
        self, project_root: Path, config: LucidScanConfig
    ) -> LucidScanFileWatcher:
        """Create a watcher instance."""
        return LucidScanFileWatcher(project_root, config)

    def test_watcher_initialization(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test watcher initialization."""
        assert watcher.project_root == project_root
        assert watcher.debounce_ms == 1000
        assert len(watcher._pending_files) == 0
        assert len(watcher._callbacks) == 0

    def test_watcher_custom_debounce(
        self, project_root: Path, config: LucidScanConfig
    ) -> None:
        """Test watcher with custom debounce."""
        watcher = LucidScanFileWatcher(
            project_root, config, debounce_ms=500
        )
        assert watcher.debounce_ms == 500

    def test_on_result_callback(self, watcher: LucidScanFileWatcher) -> None:
        """Test registering callbacks."""
        callback = MagicMock()
        watcher.on_result(callback)

        assert len(watcher._callbacks) == 1
        assert callback in watcher._callbacks

    def test_on_result_multiple_callbacks(
        self, watcher: LucidScanFileWatcher
    ) -> None:
        """Test registering multiple callbacks."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        watcher.on_result(callback1)
        watcher.on_result(callback2)

        assert len(watcher._callbacks) == 2

    def test_default_ignore_patterns(
        self, watcher: LucidScanFileWatcher
    ) -> None:
        """Test default ignore patterns."""
        assert ".git" in watcher.ignore_patterns
        assert "__pycache__" in watcher.ignore_patterns
        assert "node_modules" in watcher.ignore_patterns
        assert ".venv" in watcher.ignore_patterns
        assert ".lucidscan" in watcher.ignore_patterns

    def test_custom_ignore_patterns(
        self, project_root: Path, config: LucidScanConfig
    ) -> None:
        """Test custom ignore patterns."""
        watcher = LucidScanFileWatcher(
            project_root,
            config,
            ignore_patterns=["custom_dir", "*.log"],
        )

        assert "custom_dir" in watcher.ignore_patterns
        assert "*.log" in watcher.ignore_patterns
        # Default patterns should still be present
        assert ".git" in watcher.ignore_patterns

    def test_should_ignore_git(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test ignoring .git directory."""
        git_file = project_root / ".git" / "config"
        assert watcher._should_ignore(git_file) is True

    def test_should_ignore_pycache(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test ignoring __pycache__ directory."""
        cache_file = project_root / "__pycache__" / "module.cpython-310.pyc"
        assert watcher._should_ignore(cache_file) is True

    def test_should_ignore_node_modules(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test ignoring node_modules directory."""
        node_file = project_root / "node_modules" / "package" / "index.js"
        assert watcher._should_ignore(node_file) is True

    def test_should_ignore_pyc_files(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test ignoring .pyc files."""
        pyc_file = project_root / "src" / "module.pyc"
        assert watcher._should_ignore(pyc_file) is True

    def test_should_not_ignore_regular_files(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test that regular files are not ignored."""
        py_file = project_root / "src" / "main.py"
        assert watcher._should_ignore(py_file) is False

        js_file = project_root / "app" / "index.js"
        assert watcher._should_ignore(js_file) is False

    def test_should_not_ignore_nested_regular_files(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test that nested regular files are not ignored."""
        nested_file = project_root / "src" / "components" / "Button.tsx"
        assert watcher._should_ignore(nested_file) is False

    def test_not_running_initially(
        self, watcher: LucidScanFileWatcher
    ) -> None:
        """Test that watcher is not running initially."""
        assert watcher._running is False

    def test_stop_when_not_running(
        self, watcher: LucidScanFileWatcher
    ) -> None:
        """Test stopping when not running doesn't error."""
        watcher.stop()  # Should not raise
        assert watcher._running is False


class TestFileWatcherAsync:
    """Async tests for file watcher."""

    @pytest.fixture
    def project_root(self, tmp_path: Path) -> Path:
        """Create a temporary project root."""
        return tmp_path

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test configuration."""
        return LucidScanConfig()

    @pytest.fixture
    def watcher(
        self, project_root: Path, config: LucidScanConfig
    ) -> LucidScanFileWatcher:
        """Create a watcher instance."""
        return LucidScanFileWatcher(project_root, config, debounce_ms=10)

    @pytest.mark.asyncio
    async def test_process_pending_empty(
        self, watcher: LucidScanFileWatcher
    ) -> None:
        """Test processing with no pending files."""
        # Should complete without error
        await watcher._process_pending()
        assert len(watcher._pending_files) == 0

    @pytest.mark.asyncio
    async def test_on_file_change_ignores_directories(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test that directories are ignored in file changes."""
        dir_path = project_root / "src"
        dir_path.mkdir()

        watcher._on_file_change(dir_path)
        assert len(watcher._pending_files) == 0

    @pytest.mark.asyncio
    async def test_on_file_change_ignores_excluded(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test that excluded files are ignored."""
        git_dir = project_root / ".git"
        git_dir.mkdir()
        git_file = git_dir / "config"
        git_file.touch()

        watcher._on_file_change(git_file)
        assert len(watcher._pending_files) == 0

    @pytest.mark.asyncio
    async def test_on_file_change_adds_valid_file(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test that valid files are added to pending."""
        src_dir = project_root / "src"
        src_dir.mkdir()
        py_file = src_dir / "main.py"
        py_file.write_text("print('hello')")

        watcher._on_file_change(py_file)
        assert py_file in watcher._pending_files

    @pytest.mark.asyncio
    async def test_on_file_change_debounce_task_created(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test that debounce task is created on file change."""
        src_dir = project_root / "src"
        src_dir.mkdir()
        py_file = src_dir / "main.py"
        py_file.write_text("print('hello')")

        # Simulate event loop
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            watcher._on_file_change(py_file)
            assert watcher._debounce_task is not None
            # Cancel the task to clean up
            watcher._debounce_task.cancel()
        finally:
            loop.close()

    @pytest.mark.asyncio
    async def test_process_pending_with_files(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test processing pending files invokes scan."""
        src_dir = project_root / "src"
        src_dir.mkdir()
        py_file = src_dir / "main.py"
        py_file.write_text("print('hello')")

        # Add file to pending
        watcher._pending_files.add(py_file)

        # Register callback
        results = []
        def callback(result):
            results.append(result)
        watcher.on_result(callback)

        # Mock the executor scan
        from unittest.mock import AsyncMock
        watcher.executor.scan = AsyncMock(return_value={  # type: ignore[method-assign]
            "total_issues": 0,
            "blocking": False,
            "summary": "No issues",
            "instructions": []
        })

        # Process pending (will debounce)
        await watcher._process_pending()

        # Verify callback was invoked
        assert len(results) == 1
        assert "changed_files" in results[0]

    @pytest.mark.asyncio
    async def test_process_pending_with_callback_error(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test processing handles callback errors gracefully."""
        src_dir = project_root / "src"
        src_dir.mkdir()
        py_file = src_dir / "main.py"
        py_file.write_text("print('hello')")

        watcher._pending_files.add(py_file)

        # Register callback that raises
        def failing_callback(result):
            raise Exception("Callback failed")
        watcher.on_result(failing_callback)

        # Mock the executor scan
        from unittest.mock import AsyncMock
        watcher.executor.scan = AsyncMock(return_value={  # type: ignore[method-assign]
            "total_issues": 0,
            "blocking": False,
            "summary": "No issues",
            "instructions": []
        })

        # Should not raise
        await watcher._process_pending()

    @pytest.mark.asyncio
    async def test_process_pending_with_scan_error(
        self, watcher: LucidScanFileWatcher, project_root: Path
    ) -> None:
        """Test processing handles scan errors gracefully."""
        src_dir = project_root / "src"
        src_dir.mkdir()
        py_file = src_dir / "main.py"
        py_file.write_text("print('hello')")

        watcher._pending_files.add(py_file)

        # Register callback
        results = []
        def callback(result):
            results.append(result)
        watcher.on_result(callback)

        # Mock the executor scan to raise
        from unittest.mock import AsyncMock
        watcher.executor.scan = AsyncMock(side_effect=Exception("Scan failed"))  # type: ignore[method-assign]

        # Should not raise
        await watcher._process_pending()

        # Should have error result
        assert len(results) == 1
        assert "error" in results[0]

    @pytest.mark.asyncio
    async def test_process_pending_file_outside_project(
        self, watcher: LucidScanFileWatcher, tmp_path: Path
    ) -> None:
        """Test processing files outside project root."""
        # Create a file outside project root
        outside_file = tmp_path / "outside" / "file.py"
        outside_file.parent.mkdir()
        outside_file.write_text("print('hello')")

        watcher._pending_files.add(outside_file)

        from unittest.mock import AsyncMock
        watcher.executor.scan = AsyncMock(return_value={  # type: ignore[method-assign]
            "total_issues": 0,
            "blocking": False,
            "summary": "No issues",
            "instructions": []
        })

        # Should not raise
        await watcher._process_pending()


class TestFileChangeHandler:
    """Tests for _FileChangeHandler class."""

    def test_handler_on_modified(self, tmp_path: Path) -> None:
        """Test handler on_modified event."""
        from lucidscan.mcp.watcher import _FileChangeHandler
        from watchdog.events import FileModifiedEvent

        results = []
        def callback(path):
            results.append(path)

        handler = _FileChangeHandler(callback)

        # Create mock event
        event = FileModifiedEvent(str(tmp_path / "test.py"))

        handler.on_modified(event)

        assert len(results) == 1
        assert results[0] == Path(str(tmp_path / "test.py"))

    def test_handler_on_modified_directory(self, tmp_path: Path) -> None:
        """Test handler ignores directory modification."""
        from lucidscan.mcp.watcher import _FileChangeHandler
        from watchdog.events import DirModifiedEvent

        results = []
        def callback(path):
            results.append(path)

        handler = _FileChangeHandler(callback)

        # Create mock directory event
        event = DirModifiedEvent(str(tmp_path / "dir"))

        handler.on_modified(event)

        assert len(results) == 0

    def test_handler_on_created(self, tmp_path: Path) -> None:
        """Test handler on_created event."""
        from lucidscan.mcp.watcher import _FileChangeHandler
        from watchdog.events import FileCreatedEvent

        results = []
        def callback(path):
            results.append(path)

        handler = _FileChangeHandler(callback)

        # Create mock event
        event = FileCreatedEvent(str(tmp_path / "new.py"))

        handler.on_created(event)

        assert len(results) == 1
        assert results[0] == Path(str(tmp_path / "new.py"))

    def test_handler_on_created_directory(self, tmp_path: Path) -> None:
        """Test handler ignores directory creation."""
        from lucidscan.mcp.watcher import _FileChangeHandler
        from watchdog.events import DirCreatedEvent

        results = []
        def callback(path):
            results.append(path)

        handler = _FileChangeHandler(callback)

        # Create mock directory event
        event = DirCreatedEvent(str(tmp_path / "newdir"))

        handler.on_created(event)

        assert len(results) == 0
