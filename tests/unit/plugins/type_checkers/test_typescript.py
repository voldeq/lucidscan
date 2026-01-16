"""Unit tests for TypeScript type checker plugin.

These tests mock subprocess calls to test the parsing logic without
requiring actual TypeScript installation.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import ScanContext, Severity, ToolDomain
from lucidscan.plugins.type_checkers.typescript import TypeScriptChecker, TSC_ERROR_PATTERN


class TestTypeScriptChecker:
    """Unit tests for TypeScriptChecker."""

    def test_name(self) -> None:
        """Test name property returns correct value."""
        checker = TypeScriptChecker()
        assert checker.name == "typescript"

    def test_languages(self) -> None:
        """Test languages property returns correct value."""
        checker = TypeScriptChecker()
        assert checker.languages == ["typescript"]

    def test_supports_strict_mode(self) -> None:
        """Test supports_strict_mode property returns True."""
        checker = TypeScriptChecker()
        assert checker.supports_strict_mode is True

    def test_get_version_success(self) -> None:
        """Test get_version with successful subprocess call."""
        checker = TypeScriptChecker()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Version 5.3.3"

        with patch.object(checker, "ensure_binary", return_value=Path("/usr/bin/tsc")):
            with patch("subprocess.run", return_value=mock_result):
                version = checker.get_version()
                assert version == "5.3.3"

    def test_get_version_failure(self) -> None:
        """Test get_version returns unknown on failure."""
        checker = TypeScriptChecker()

        with patch.object(checker, "ensure_binary", side_effect=FileNotFoundError()):
            version = checker.get_version()
            assert version == "unknown"

    def test_get_version_invalid_output(self) -> None:
        """Test get_version handles invalid output."""
        checker = TypeScriptChecker()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""  # Empty output

        with patch.object(checker, "ensure_binary", return_value=Path("/usr/bin/tsc")):
            with patch("subprocess.run", return_value=mock_result):
                version = checker.get_version()
                assert version == "unknown"

    def test_ensure_binary_project_node_modules(self) -> None:
        """Test ensure_binary finds tsc in project node_modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create node_modules/.bin/tsc
            bin_dir = tmpdir_path / "node_modules" / ".bin"
            bin_dir.mkdir(parents=True)
            tsc_path = bin_dir / "tsc"
            tsc_path.touch()

            checker = TypeScriptChecker(project_root=tmpdir_path)
            binary = checker.ensure_binary()
            assert binary == tsc_path

    def test_ensure_binary_system_path(self) -> None:
        """Test ensure_binary finds tsc in system PATH."""
        checker = TypeScriptChecker()

        with patch("shutil.which", return_value="/usr/local/bin/tsc"):
            binary = checker.ensure_binary()
            assert binary == Path("/usr/local/bin/tsc")

    def test_ensure_binary_not_found(self) -> None:
        """Test ensure_binary raises when tsc not found."""
        checker = TypeScriptChecker()

        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError) as exc_info:
                checker.ensure_binary()
            assert "TypeScript is not installed" in str(exc_info.value)

    def test_check_no_binary(self) -> None:
        """Test check returns empty when binary not found."""
        checker = TypeScriptChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(checker, "ensure_binary", side_effect=FileNotFoundError("not found")):
                issues = checker.check(context)
                assert issues == []

    def test_check_no_tsconfig(self) -> None:
        """Test check returns empty when no tsconfig.json."""
        checker = TypeScriptChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(checker, "ensure_binary", return_value=Path("/usr/bin/tsc")):
                issues = checker.check(context)
                assert issues == []

    def test_check_success(self) -> None:
        """Test check parses output correctly."""
        checker = TypeScriptChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create tsconfig.json
            tsconfig = tmpdir_path / "tsconfig.json"
            tsconfig.write_text("{}")

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stdout = "src/test.ts(10,5): error TS2322: Type 'string' is not assignable to type 'number'."
            mock_result.stderr = ""

            with patch.object(checker, "ensure_binary", return_value=Path("/usr/bin/tsc")):
                with patch("subprocess.run", return_value=mock_result):
                    issues = checker.check(context)

                    assert len(issues) == 1
                    assert issues[0].source_tool == "typescript"
                    assert issues[0].domain == ToolDomain.TYPE_CHECKING
                    assert "TS2322" in issues[0].title
                    assert issues[0].line_start == 10
                    assert issues[0].severity == Severity.HIGH

    def test_check_timeout(self) -> None:
        """Test check handles timeout."""
        checker = TypeScriptChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            tsconfig = tmpdir_path / "tsconfig.json"
            tsconfig.write_text("{}")

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            with patch.object(checker, "ensure_binary", return_value=Path("/usr/bin/tsc")):
                with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tsc", 180)):
                    issues = checker.check(context)
                    assert issues == []

    def test_check_subprocess_error(self) -> None:
        """Test check handles subprocess error."""
        checker = TypeScriptChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            tsconfig = tmpdir_path / "tsconfig.json"
            tsconfig.write_text("{}")

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            with patch.object(checker, "ensure_binary", return_value=Path("/usr/bin/tsc")):
                with patch("subprocess.run", side_effect=OSError("command failed")):
                    issues = checker.check(context)
                    assert issues == []


class TestTypeScriptOutputParsing:
    """Tests for TypeScript output parsing."""

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        checker = TypeScriptChecker()
        issues = checker._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_single_error(self) -> None:
        """Test parsing single error."""
        checker = TypeScriptChecker()
        output = "src/test.ts(10,5): error TS2322: Type 'string' is not assignable to type 'number'."
        issues = checker._parse_output(output, Path("/project"))

        assert len(issues) == 1
        assert issues[0].line_start == 10
        assert "TS2322" in issues[0].title
        assert issues[0].severity == Severity.HIGH

    def test_parse_warning(self) -> None:
        """Test parsing warning severity."""
        checker = TypeScriptChecker()
        output = "src/test.ts(5,1): warning TS6133: 'x' is declared but its value is never read."
        issues = checker._parse_output(output, Path("/project"))

        assert len(issues) == 1
        assert issues[0].severity == Severity.MEDIUM

    def test_parse_multiple_errors(self) -> None:
        """Test parsing multiple errors."""
        checker = TypeScriptChecker()
        output = """src/a.ts(1,5): error TS2322: Type error 1.
src/b.ts(10,1): error TS2345: Type error 2.
src/c.ts(20,10): warning TS6133: Warning."""

        issues = checker._parse_output(output, Path("/project"))

        assert len(issues) == 3

    def test_parse_skips_non_matching_lines(self) -> None:
        """Test parsing skips lines that don't match pattern."""
        checker = TypeScriptChecker()
        output = """Some random output
src/test.ts(10,5): error TS2322: Actual error.
More random stuff"""

        issues = checker._parse_output(output, Path("/project"))

        assert len(issues) == 1

    def test_parse_relative_path(self) -> None:
        """Test that relative paths are resolved."""
        checker = TypeScriptChecker()
        output = "src/test.ts(10,5): error TS2322: Type error."
        issues = checker._parse_output(output, Path("/project"))

        assert len(issues) == 1
        # Use Path for cross-platform comparison
        assert issues[0].file_path == Path("/project/src/test.ts")

    def test_parse_absolute_path(self) -> None:
        """Test that absolute paths are preserved."""
        checker = TypeScriptChecker()
        output = "/absolute/path/test.ts(10,5): error TS2322: Type error."
        issues = checker._parse_output(output, Path("/project"))

        assert len(issues) == 1
        # Use Path for cross-platform comparison
        assert issues[0].file_path == Path("/absolute/path/test.ts")


class TestTscErrorPattern:
    """Tests for the TSC error regex pattern."""

    def test_matches_standard_error(self) -> None:
        """Test pattern matches standard TypeScript error."""
        line = "src/test.ts(10,5): error TS2322: Type 'string' is not assignable."
        match = TSC_ERROR_PATTERN.match(line)

        assert match is not None
        assert match.group(1) == "src/test.ts"
        assert match.group(2) == "10"
        assert match.group(3) == "5"
        assert match.group(4) == "error"
        assert match.group(5) == "TS2322"
        assert match.group(6) == "Type 'string' is not assignable."

    def test_matches_warning(self) -> None:
        """Test pattern matches warning."""
        line = "src/test.ts(5,1): warning TS6133: 'x' is declared but never read."
        match = TSC_ERROR_PATTERN.match(line)

        assert match is not None
        assert match.group(4) == "warning"

    def test_matches_windows_path(self) -> None:
        """Test pattern matches Windows-style paths."""
        line = "C:\\project\\src\\test.ts(10,5): error TS2322: Type error."
        match = TSC_ERROR_PATTERN.match(line)

        assert match is not None
        assert match.group(1) == "C:\\project\\src\\test.ts"

    def test_no_match_invalid_format(self) -> None:
        """Test pattern doesn't match invalid format."""
        invalid_lines = [
            "Just some text",
            "src/test.ts: error",  # Missing line/col
            "error TS2322: Type error.",  # Missing file
        ]

        for line in invalid_lines:
            match = TSC_ERROR_PATTERN.match(line)
            assert match is None, f"Should not match: {line}"


class TestIssueIdGeneration:
    """Tests for issue ID generation."""

    def test_generate_issue_id_deterministic(self) -> None:
        """Test that issue IDs are deterministic."""
        checker = TypeScriptChecker()

        id1 = checker._generate_issue_id("TS2322", "test.ts", 10, 5, "Type error")
        id2 = checker._generate_issue_id("TS2322", "test.ts", 10, 5, "Type error")

        assert id1 == id2

    def test_generate_issue_id_different_inputs(self) -> None:
        """Test that different inputs produce different IDs."""
        checker = TypeScriptChecker()

        id1 = checker._generate_issue_id("TS2322", "test.ts", 10, 5, "Type error")
        id2 = checker._generate_issue_id("TS2345", "test.ts", 10, 5, "Type error")

        assert id1 != id2

    def test_generate_issue_id_format(self) -> None:
        """Test issue ID format."""
        checker = TypeScriptChecker()

        issue_id = checker._generate_issue_id("TS2322", "test.ts", 10, 5, "Type error")

        assert issue_id.startswith("ts-TS2322-")
        assert len(issue_id) == len("ts-TS2322-") + 12  # 12 char hash
