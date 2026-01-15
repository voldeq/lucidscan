"""Unit tests for tool version management."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.bootstrap.versions import (
    _FALLBACK_VERSIONS,
    _load_pyproject_versions,
    get_tool_version,
    get_all_versions,
)


class TestLoadPyprojectVersions:
    """Tests for _load_pyproject_versions."""

    def test_returns_dict(self) -> None:
        """Test that function returns a dictionary."""
        # Clear cache to ensure fresh load
        _load_pyproject_versions.cache_clear()
        result = _load_pyproject_versions()
        assert isinstance(result, dict)

    def test_fallback_when_tomllib_none(self) -> None:
        """Test fallback when tomllib is not available."""
        _load_pyproject_versions.cache_clear()

        with patch("lucidscan.bootstrap.versions._tomllib", None):
            # Need to reload to pick up the patched value
            from lucidscan.bootstrap import versions as v

            v._load_pyproject_versions.cache_clear()

            # Directly test the condition
            result = v._load_pyproject_versions()
            # Should return fallback versions
            assert isinstance(result, dict)

    def test_fallback_when_pyproject_not_exists(self) -> None:
        """Test fallback when pyproject.toml doesn't exist."""
        _load_pyproject_versions.cache_clear()

        with patch("pathlib.Path.exists", return_value=False):
            from lucidscan.bootstrap import versions as v

            v._load_pyproject_versions.cache_clear()

            # With mocked non-existent pyproject.toml, should use fallbacks
            with patch.object(Path, "exists", return_value=False):
                result = v._load_pyproject_versions()
                assert isinstance(result, dict)

    def test_fallback_on_exception(self) -> None:
        """Test fallback when pyproject.toml parsing fails."""
        _load_pyproject_versions.cache_clear()

        mock_tomllib = MagicMock()
        mock_tomllib.load.side_effect = Exception("Parse error")

        with patch("lucidscan.bootstrap.versions._tomllib", mock_tomllib):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("builtins.open", MagicMock()):
                    from lucidscan.bootstrap import versions as v

                    v._load_pyproject_versions.cache_clear()
                    result = v._load_pyproject_versions()
                    # Should return fallback versions on exception
                    assert isinstance(result, dict)

    def test_loads_from_tools_section(self) -> None:
        """Test loading versions from [tool.lucidscan.tools] section."""
        _load_pyproject_versions.cache_clear()

        mock_data = {
            "tool": {
                "lucidscan": {
                    "tools": {
                        "trivy": "1.0.0",
                        "ruff": "2.0.0",
                    }
                }
            }
        }

        mock_tomllib = MagicMock()
        mock_tomllib.load.return_value = mock_data

        with patch("lucidscan.bootstrap.versions._tomllib", mock_tomllib):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("builtins.open", MagicMock()):
                    from lucidscan.bootstrap import versions as v

                    v._load_pyproject_versions.cache_clear()
                    result = v._load_pyproject_versions()

                    assert result.get("trivy") == "1.0.0"
                    assert result.get("ruff") == "2.0.0"

    def test_loads_from_legacy_scanners_section(self) -> None:
        """Test loading versions from legacy [tool.lucidscan.scanners] section."""
        _load_pyproject_versions.cache_clear()

        mock_data = {
            "tool": {
                "lucidscan": {
                    "tools": {},  # Empty tools section
                    "scanners": {
                        "trivy": "1.0.0",  # Legacy section
                    }
                }
            }
        }

        mock_tomllib = MagicMock()
        mock_tomllib.load.return_value = mock_data

        with patch("lucidscan.bootstrap.versions._tomllib", mock_tomllib):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("builtins.open", MagicMock()):
                    from lucidscan.bootstrap import versions as v

                    v._load_pyproject_versions.cache_clear()
                    result = v._load_pyproject_versions()

                    assert result.get("trivy") == "1.0.0"

    def test_tools_section_takes_precedence(self) -> None:
        """Test that tools section takes precedence over scanners section."""
        _load_pyproject_versions.cache_clear()

        mock_data = {
            "tool": {
                "lucidscan": {
                    "tools": {
                        "trivy": "2.0.0",  # Should win
                    },
                    "scanners": {
                        "trivy": "1.0.0",  # Should be ignored
                    }
                }
            }
        }

        mock_tomllib = MagicMock()
        mock_tomllib.load.return_value = mock_data

        with patch("lucidscan.bootstrap.versions._tomllib", mock_tomllib):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("builtins.open", MagicMock()):
                    from lucidscan.bootstrap import versions as v

                    v._load_pyproject_versions.cache_clear()
                    result = v._load_pyproject_versions()

                    assert result.get("trivy") == "2.0.0"

    def test_fills_missing_from_fallbacks(self) -> None:
        """Test that missing tools are filled from fallbacks."""
        _load_pyproject_versions.cache_clear()

        # Only provide one tool version
        mock_data = {
            "tool": {
                "lucidscan": {
                    "tools": {
                        "trivy": "1.0.0",
                    }
                }
            }
        }

        mock_tomllib = MagicMock()
        mock_tomllib.load.return_value = mock_data

        with patch("lucidscan.bootstrap.versions._tomllib", mock_tomllib):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("builtins.open", MagicMock()):
                    from lucidscan.bootstrap import versions as v

                    v._load_pyproject_versions.cache_clear()
                    result = v._load_pyproject_versions()

                    # Should have trivy from pyproject
                    assert result.get("trivy") == "1.0.0"
                    # Should have ruff from fallbacks
                    assert "ruff" in result


class TestGetToolVersion:
    """Tests for get_tool_version."""

    def test_get_known_tool(self) -> None:
        """Test getting version for a known tool."""
        # Trivy should always be available (either from pyproject or fallback)
        version = get_tool_version("trivy")
        assert version is not None
        assert isinstance(version, str)

    def test_get_unknown_tool_with_default(self) -> None:
        """Test getting version for unknown tool with default."""
        version = get_tool_version("unknown_tool", default="1.0.0")
        assert version == "1.0.0"

    def test_get_unknown_tool_without_default(self) -> None:
        """Test getting version for unknown tool without default raises."""
        with pytest.raises(KeyError) as exc_info:
            get_tool_version("completely_unknown_tool_xyz")

        assert "completely_unknown_tool_xyz" in str(exc_info.value)
        assert "Available" in str(exc_info.value)

    def test_get_all_fallback_tools(self) -> None:
        """Test that all fallback tools are retrievable."""
        for tool_name in _FALLBACK_VERSIONS:
            version = get_tool_version(tool_name)
            assert version is not None
            assert isinstance(version, str)


class TestGetAllVersions:
    """Tests for get_all_versions."""

    def test_returns_dict(self) -> None:
        """Test that function returns a dictionary."""
        result = get_all_versions()
        assert isinstance(result, dict)

    def test_returns_copy(self) -> None:
        """Test that function returns a copy, not the original."""
        result1 = get_all_versions()
        result2 = get_all_versions()

        # Modify one
        result1["test_key"] = "test_value"

        # Other should not be affected
        assert "test_key" not in result2

    def test_contains_expected_tools(self) -> None:
        """Test that result contains expected tools."""
        result = get_all_versions()

        # Should contain at least the fallback tools
        for tool in ["trivy", "ruff", "biome"]:
            assert tool in result


class TestFallbackVersions:
    """Tests for fallback version constants."""

    def test_fallback_versions_not_empty(self) -> None:
        """Test that fallback versions are defined."""
        assert len(_FALLBACK_VERSIONS) > 0

    def test_fallback_versions_are_strings(self) -> None:
        """Test that all fallback versions are strings."""
        for tool, version in _FALLBACK_VERSIONS.items():
            assert isinstance(tool, str)
            assert isinstance(version, str)

    def test_fallback_versions_format(self) -> None:
        """Test that fallback versions look like version strings."""
        for tool, version in _FALLBACK_VERSIONS.items():
            # Versions should have at least one dot (e.g., "1.0" or "1.0.0")
            assert "." in version, f"{tool} version '{version}' doesn't look like a version"

    def test_expected_tools_in_fallback(self) -> None:
        """Test that expected tools are in fallback versions."""
        expected_tools = ["trivy", "opengrep", "checkov", "ruff", "biome", "checkstyle", "pyright"]
        for tool in expected_tools:
            assert tool in _FALLBACK_VERSIONS, f"Expected {tool} in fallback versions"
