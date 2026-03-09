"""Unit tests for FormatterPlugin base class."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Union, Tuple

import pytest

from lucidshark.core.models import ScanContext, ToolDomain, UnifiedIssue
from lucidshark.plugins.formatters.base import FormatterPlugin
from lucidshark.plugins.linters.base import FixResult


class ConcreteFormatter(FormatterPlugin):
    """Concrete implementation for testing."""

    @property
    def name(self) -> str:
        return "test_formatter"

    @property
    def languages(self) -> List[str]:
        return ["python"]

    def ensure_binary(self) -> Union[Path, Tuple[Path, str]]:
        return Path("/usr/bin/test-formatter")

    def check(self, context: ScanContext) -> List[UnifiedIssue]:
        return []

    def fix(self, context: ScanContext) -> FixResult:
        return FixResult()


class TestFormatterPluginProperties:
    """Tests for FormatterPlugin basic properties."""

    def test_domain_is_formatting(self) -> None:
        formatter = ConcreteFormatter()
        assert formatter.domain == ToolDomain.FORMATTING

    def test_supports_fix_true_by_default(self) -> None:
        formatter = ConcreteFormatter()
        assert formatter.supports_fix is True

    def test_get_version_default(self) -> None:
        formatter = ConcreteFormatter()
        assert formatter.get_version() == "installed"

    def test_name(self) -> None:
        formatter = ConcreteFormatter()
        assert formatter.name == "test_formatter"

    def test_languages(self) -> None:
        formatter = ConcreteFormatter()
        assert formatter.languages == ["python"]

    def test_init_with_project_root(self) -> None:
        formatter = ConcreteFormatter(project_root=Path("/tmp/test"))
        assert formatter._project_root == Path("/tmp/test")

    def test_init_default_project_root_is_none(self) -> None:
        """Verify _project_root is None when not provided."""
        formatter = ConcreteFormatter()
        assert formatter._project_root is None

    def test_init_accepts_extra_kwargs(self) -> None:
        """Verify **kwargs are silently accepted without error."""
        formatter = ConcreteFormatter(
            project_root=Path("/tmp"),
            extra_param="value",
            another=42,
        )
        assert formatter._project_root == Path("/tmp")

    def test_fix_returns_fix_result(self) -> None:
        """Concrete fix() should return a FixResult."""
        formatter = ConcreteFormatter()
        result = formatter.fix(None)  # type: ignore
        assert isinstance(result, FixResult)

    def test_cannot_instantiate_abstract_class(self) -> None:
        """FormatterPlugin itself cannot be instantiated."""
        with pytest.raises(TypeError):
            FormatterPlugin()  # type: ignore

    def test_cannot_instantiate_without_fix(self) -> None:
        """Subclass without fix() cannot be instantiated."""

        class IncompleteFormatter(FormatterPlugin):
            @property
            def name(self) -> str:
                return "incomplete"

            @property
            def languages(self) -> List[str]:
                return ["python"]

            def ensure_binary(self) -> Union[Path, Tuple[Path, str]]:
                return Path("/usr/bin/test")

            def check(self, context: ScanContext) -> List[UnifiedIssue]:
                return []

        with pytest.raises(TypeError):
            IncompleteFormatter()  # type: ignore


class TestResolvePathsFallbackToCwd:
    """Tests for _resolve_paths with fallback_to_cwd=True (ruff, prettier style)."""

    def test_empty_paths_returns_dot(self) -> None:
        formatter = ConcreteFormatter()
        context = ScanContext(
            project_root=Path("/tmp"),
            paths=[],
            enabled_domains=[ToolDomain.FORMATTING],
        )
        result = formatter._resolve_paths(context, {".py"}, fallback_to_cwd=True)
        assert result == ["."]

    def test_filters_by_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            py_file = root / "test.py"
            py_file.touch()
            js_file = root / "test.js"
            js_file.touch()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[py_file, js_file],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".py"}, fallback_to_cwd=True)
            assert result == [str(py_file)]

    def test_directories_passed_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subdir = root / "src"
            subdir.mkdir()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[subdir],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".py"}, fallback_to_cwd=True)
            assert str(subdir) in result

    def test_mixed_files_and_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subdir = root / "src"
            subdir.mkdir()
            py_file = root / "test.py"
            py_file.touch()
            js_file = root / "test.js"
            js_file.touch()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[subdir, py_file, js_file],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".py"}, fallback_to_cwd=True)
            assert len(result) == 2
            assert str(subdir) in result
            assert str(py_file) in result


class TestResolvePathsWithDiscovery:
    """Tests for _resolve_paths with fallback_to_cwd=False (rustfmt, google-java-format style)."""

    def test_empty_paths_discovers_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rs_file = root / "main.rs"
            rs_file.touch()
            py_file = root / "main.py"
            py_file.touch()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".rs"}, fallback_to_cwd=False)
            assert result == [str(rs_file)]

    def test_directories_expanded_to_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            subdir = root / "src"
            subdir.mkdir()
            rs_file = subdir / "lib.rs"
            rs_file.touch()
            py_file = subdir / "lib.py"
            py_file.touch()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[subdir],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".rs"}, fallback_to_cwd=False)
            assert result == [str(rs_file)]

    def test_skips_non_matching_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            py_file = root / "main.py"
            py_file.touch()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[py_file],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".rs"}, fallback_to_cwd=False)
            assert result == []

    def test_includes_matching_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rs_file = root / "main.rs"
            rs_file.touch()

            formatter = ConcreteFormatter()
            context = ScanContext(
                project_root=root,
                paths=[rs_file],
                enabled_domains=[ToolDomain.FORMATTING],
            )
            result = formatter._resolve_paths(context, {".rs"}, fallback_to_cwd=False)
            assert result == [str(rs_file)]
