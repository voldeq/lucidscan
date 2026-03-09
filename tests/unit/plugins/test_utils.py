"""Unit tests for shared plugin utilities."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


from lucidshark.plugins.utils import (
    coverage_has_source_config,
    detect_source_directory,
    get_cli_version,
    resolve_src_paths,
)


class TestGetCliVersion:
    """Tests for get_cli_version function."""

    def test_returns_version_on_success(self) -> None:
        """Test successful version retrieval."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1.2.3"

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"))

        assert version == "1.2.3"

    def test_returns_unknown_on_empty_output(self) -> None:
        """Test returns 'unknown' when output is empty."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"))

        assert version == "unknown"

    def test_returns_unknown_on_whitespace_output(self) -> None:
        """Test returns 'unknown' when output is only whitespace."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "   \n\t  "

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"))

        assert version == "unknown"

    def test_returns_unknown_on_exception(self) -> None:
        """Test returns 'unknown' when subprocess raises exception."""
        with patch("subprocess.run", side_effect=OSError("Command not found")):
            version = get_cli_version(Path("/usr/bin/nonexistent"))

        assert version == "unknown"

    def test_returns_unknown_on_timeout(self) -> None:
        """Test returns 'unknown' when subprocess times out."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            version = get_cli_version(Path("/usr/bin/slow"))

        assert version == "unknown"

    def test_returns_unknown_on_nonzero_exit(self) -> None:
        """Test returns 'unknown' when command exits with error."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/failing"))

        assert version == "unknown"

    def test_uses_custom_parser(self) -> None:
        """Test custom parser function is used."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Version 2.0.0"

        def extract_version(s: str) -> str:
            return s.split()[1]

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"), parser=extract_version)

        assert version == "2.0.0"

    def test_returns_unknown_when_parser_returns_empty(self) -> None:
        """Test returns 'unknown' when parser returns empty string."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid output"

        def bad_parser(s: str) -> str:
            return ""  # Always returns empty

        with patch("subprocess.run", return_value=mock_result):
            version = get_cli_version(Path("/usr/bin/tool"), parser=bad_parser)

        assert version == "unknown"


class TestResolveSrcPaths:
    """Tests for resolve_src_paths function."""

    def test_returns_context_paths_when_provided(self) -> None:
        """Test that explicit context paths are returned as-is."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            context_paths = [
                project_root / "file1.py",
                project_root / "file2.py",
            ]

            result = resolve_src_paths(context_paths, project_root)

            assert len(result) == 2
            assert result[0].endswith("file1.py")
            assert result[1].endswith("file2.py")

    def test_returns_src_dir_when_exists(self) -> None:
        """Test fallback to src directory when it exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_dir = project_root / "src"
            src_dir.mkdir()

            result = resolve_src_paths(None, project_root)

            assert len(result) == 1
            assert result[0].endswith("src")

    def test_returns_dot_when_src_not_exists(self) -> None:
        """Test fallback to '.' when src directory doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            # Don't create src directory

            result = resolve_src_paths(None, project_root)

            assert result == ["."]

    def test_uses_custom_default_subdir(self) -> None:
        """Test custom default subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            lib_dir = project_root / "lib"
            lib_dir.mkdir()

            result = resolve_src_paths(None, project_root, default_subdir="lib")

            assert len(result) == 1
            assert result[0].endswith("lib")

    def test_empty_context_paths_treated_as_none(self) -> None:
        """Test that empty context paths list falls back to default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            src_dir = project_root / "src"
            src_dir.mkdir()

            # Empty list should fall back to src directory
            result = resolve_src_paths([], project_root)

            # Empty list is falsy, so should fall back
            assert result == ["."] or result[0].endswith("src")


class TestDetectSourceDirectory:
    """Tests for detect_source_directory function."""

    def test_src_package_layout(self) -> None:
        """Test detection of src/<package>/ layout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            pkg = project_root / "src" / "mypackage"
            pkg.mkdir(parents=True)
            (pkg / "__init__.py").touch()

            result = detect_source_directory(project_root)

            assert result == "src/mypackage"

    def test_src_dir_without_package(self) -> None:
        """Test fallback to src/ when no package with __init__.py inside."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            (project_root / "src").mkdir()

            result = detect_source_directory(project_root)

            assert result == "src"

    def test_flat_package_layout(self) -> None:
        """Test detection of flat <project_name>/ layout at root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Name the project root so the heuristic can derive package name
            project_root = Path(tmpdir) / "my-project"
            project_root.mkdir()
            pkg = project_root / "my_project"
            pkg.mkdir()
            (pkg / "__init__.py").touch()

            result = detect_source_directory(project_root)

            assert result == "my_project"

    def test_pyproject_toml_packages_where(self) -> None:
        """Test reading [tool.setuptools.packages.find] where from pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            pyproject = project_root / "pyproject.toml"
            pyproject.write_text('[tool.setuptools.packages.find]\nwhere = ["lib"]\n')

            result = detect_source_directory(project_root)

            assert result == "lib"

    def test_returns_none_when_nothing_detected(self) -> None:
        """Test returns None when no source directory can be found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            result = detect_source_directory(project_root)

            assert result is None

    def test_src_layout_preferred_over_flat(self) -> None:
        """Test that src/ layout is checked before flat layout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir) / "my-project"
            project_root.mkdir()
            # Create both layouts
            src_pkg = project_root / "src" / "my_project"
            src_pkg.mkdir(parents=True)
            (src_pkg / "__init__.py").touch()
            flat_pkg = project_root / "my_project"
            flat_pkg.mkdir()
            (flat_pkg / "__init__.py").touch()

            result = detect_source_directory(project_root)

            # src/ layout should win
            assert result == "src/my_project"


class TestCoverageHasSourceConfig:
    """Tests for coverage_has_source_config function."""

    def test_pyproject_toml_with_source(self) -> None:
        """Test detection of [tool.coverage.run] source in pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            pyproject = project_root / "pyproject.toml"
            pyproject.write_text('[tool.coverage.run]\nsource = ["src/mypackage"]\n')

            assert coverage_has_source_config(project_root) is True

    def test_pyproject_toml_without_coverage_section(self) -> None:
        """Test returns False when no coverage config in pyproject.toml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            pyproject = project_root / "pyproject.toml"
            pyproject.write_text("[project]\nname = 'foo'\n")

            assert coverage_has_source_config(project_root) is False

    def test_coveragerc_with_source(self) -> None:
        """Test detection of source in .coveragerc."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            coveragerc = project_root / ".coveragerc"
            coveragerc.write_text("[run]\nsource = src/mypackage\n")

            assert coverage_has_source_config(project_root) is True

    def test_setup_cfg_with_coverage_source(self) -> None:
        """Test detection of source in setup.cfg [coverage:run]."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            setup_cfg = project_root / "setup.cfg"
            setup_cfg.write_text("[coverage:run]\nsource = src/mypackage\n")

            assert coverage_has_source_config(project_root) is True

    def test_no_config_files(self) -> None:
        """Test returns False when no config files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)

            assert coverage_has_source_config(project_root) is False

    def test_pyproject_toml_empty_source(self) -> None:
        """Test returns False when source is an empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            pyproject = project_root / "pyproject.toml"
            pyproject.write_text("[tool.coverage.run]\nsource = []\n")

            assert coverage_has_source_config(project_root) is False
