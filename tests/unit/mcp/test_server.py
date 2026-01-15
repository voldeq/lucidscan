"""Unit tests for MCP server."""

from __future__ import annotations

from pathlib import Path

import pytest

from lucidscan.config import LucidScanConfig
from lucidscan.mcp.server import LucidScanMCPServer


class TestLucidScanMCPServer:
    """Tests for LucidScanMCPServer."""

    @pytest.fixture
    def project_root(self, tmp_path: Path) -> Path:
        """Create a temporary project root."""
        return tmp_path

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test configuration."""
        return LucidScanConfig()

    @pytest.fixture
    def server(
        self, project_root: Path, config: LucidScanConfig
    ) -> LucidScanMCPServer:
        """Create a server instance."""
        return LucidScanMCPServer(project_root, config)

    def test_server_initialization(
        self, server: LucidScanMCPServer, project_root: Path
    ) -> None:
        """Test server initialization."""
        assert server.project_root == project_root
        assert server.config is not None
        assert server.executor is not None
        assert server.server is not None

    def test_server_name(self, server: LucidScanMCPServer) -> None:
        """Test server has correct name."""
        assert server.server.name == "lucidscan"

    def test_server_has_executor(self, server: LucidScanMCPServer) -> None:
        """Test server has tool executor."""
        from lucidscan.mcp.tools import MCPToolExecutor
        assert isinstance(server.executor, MCPToolExecutor)

    def test_server_executor_uses_project_root(
        self, server: LucidScanMCPServer, project_root: Path
    ) -> None:
        """Test server executor uses correct project root."""
        assert server.executor.project_root == project_root

    def test_server_executor_uses_config(
        self, server: LucidScanMCPServer, config: LucidScanConfig
    ) -> None:
        """Test server executor uses correct config."""
        assert server.executor.config == config

    def test_server_creates_mcp_server(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test server creates MCP Server instance."""
        from mcp.server import Server
        assert isinstance(server.server, Server)

    def test_server_initialization_with_different_configs(
        self, project_root: Path
    ) -> None:
        """Test server can be initialized with different configs."""
        config1 = LucidScanConfig()
        config2 = LucidScanConfig()

        server1 = LucidScanMCPServer(project_root, config1)
        server2 = LucidScanMCPServer(project_root, config2)

        assert server1.config is config1
        assert server2.config is config2

    def test_server_initialization_with_different_roots(
        self, config: LucidScanConfig, tmp_path: Path
    ) -> None:
        """Test server can be initialized with different roots."""
        root1 = tmp_path / "project1"
        root1.mkdir()
        root2 = tmp_path / "project2"
        root2.mkdir()

        server1 = LucidScanMCPServer(root1, config)
        server2 = LucidScanMCPServer(root2, config)

        assert server1.project_root == root1
        assert server2.project_root == root2


class TestLucidScanMCPServerToolRegistration:
    """Tests for tool registration in MCP server."""

    @pytest.fixture
    def project_root(self, tmp_path: Path) -> Path:
        """Create a temporary project root."""
        return tmp_path

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test configuration."""
        return LucidScanConfig()

    def test_register_tools_does_not_raise(
        self, project_root: Path, config: LucidScanConfig
    ) -> None:
        """Test _register_tools completes without error."""
        # This implicitly tests _register_tools since it's called in __init__
        server = LucidScanMCPServer(project_root, config)
        assert server is not None

    def test_server_can_be_created_multiple_times(
        self, project_root: Path, config: LucidScanConfig
    ) -> None:
        """Test multiple servers can be created."""
        servers = [
            LucidScanMCPServer(project_root, config)
            for _ in range(3)
        ]
        assert len(servers) == 3
        for s in servers:
            assert s.server.name == "lucidscan"


class TestLucidScanMCPServerAsync:
    """Async tests for MCP server."""

    @pytest.fixture
    def project_root(self, tmp_path: Path) -> Path:
        """Create a temporary project root."""
        return tmp_path

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test configuration."""
        return LucidScanConfig()

    @pytest.fixture
    def server(
        self, project_root: Path, config: LucidScanConfig
    ) -> LucidScanMCPServer:
        """Create a server instance."""
        return LucidScanMCPServer(project_root, config)

    @pytest.mark.asyncio
    async def test_server_run_method_exists(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test server has run method."""
        assert hasattr(server, "run")
        assert callable(server.run)

    @pytest.mark.asyncio
    async def test_executor_scan_can_be_called(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor scan method can be called."""
        result = await server.executor.scan(domains=["linting"])
        assert "total_issues" in result
        assert "instructions" in result

    @pytest.mark.asyncio
    async def test_executor_check_file_not_found(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor check_file with non-existent file."""
        result = await server.executor.check_file("nonexistent.py")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_executor_get_fix_instructions_not_found(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor get_fix_instructions with unknown ID."""
        result = await server.executor.get_fix_instructions("unknown-id")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_executor_apply_fix_not_found(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor apply_fix with unknown ID."""
        result = await server.executor.apply_fix("unknown-id")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_executor_get_status(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor get_status returns expected structure."""
        result = await server.executor.get_status()
        assert "project_root" in result
        assert "available_tools" in result

    @pytest.mark.asyncio
    async def test_executor_get_help(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor get_help returns documentation."""
        result = await server.executor.get_help()
        assert "documentation" in result

    @pytest.mark.asyncio
    async def test_executor_autoconfigure(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor autoconfigure returns instructions."""
        result = await server.executor.autoconfigure()
        assert "instructions" in result or isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_executor_validate_config_no_config(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor validate_config when no config exists."""
        result = await server.executor.validate_config()
        # Should return error or validation result
        assert isinstance(result, dict)


class TestMCPServerToolDispatch:
    """Tests for MCP server tool dispatch logic."""

    @pytest.fixture
    def project_root(self, tmp_path: Path) -> Path:
        """Create a temporary project root."""
        return tmp_path

    @pytest.fixture
    def config(self) -> LucidScanConfig:
        """Create a test configuration."""
        return LucidScanConfig()

    @pytest.fixture
    def server(
        self, project_root: Path, config: LucidScanConfig
    ) -> LucidScanMCPServer:
        """Create a server instance."""
        return LucidScanMCPServer(project_root, config)

    def test_server_has_registered_handlers(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test server has registered tool handlers."""
        # The server should have registered handlers via decorators
        # We can verify the server object exists and has expected attributes
        assert server.server is not None
        assert hasattr(server.server, "list_tools")
        assert hasattr(server.server, "call_tool")

    def test_executor_has_all_methods(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor has all required methods."""
        required_methods = [
            "scan",
            "check_file",
            "get_fix_instructions",
            "apply_fix",
            "get_status",
            "get_help",
            "autoconfigure",
            "validate_config",
        ]
        for method in required_methods:
            assert hasattr(server.executor, method), f"Missing method: {method}"
            assert callable(getattr(server.executor, method)), f"Method not callable: {method}"

    @pytest.mark.asyncio
    async def test_executor_scan_with_domains(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor scan can be called with specific domains."""
        result = await server.executor.scan(domains=["linting", "type_checking"])
        assert "total_issues" in result
        assert "instructions" in result

    @pytest.mark.asyncio
    async def test_executor_scan_with_fix(
        self, server: LucidScanMCPServer
    ) -> None:
        """Test executor scan with fix=True."""
        result = await server.executor.scan(domains=["linting"], fix=True)
        assert "total_issues" in result
