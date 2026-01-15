"""Unit tests for ESLint linter plugin.

These tests mock subprocess calls to test the parsing logic without
requiring actual ESLint installation.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidscan.core.models import ScanContext, Severity, ToolDomain
from lucidscan.plugins.linters.eslint import ESLintLinter, SEVERITY_MAP


def make_completed_process(returncode: int, stdout: str, stderr: str = "") -> subprocess.CompletedProcess:
    """Create a CompletedProcess for testing."""
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class TestESLintLinter:
    """Unit tests for ESLintLinter."""

    def test_name(self) -> None:
        """Test name property returns correct value."""
        linter = ESLintLinter()
        assert linter.name == "eslint"

    def test_languages(self) -> None:
        """Test languages property returns correct value."""
        linter = ESLintLinter()
        assert linter.languages == ["javascript", "typescript"]

    def test_supports_fix(self) -> None:
        """Test supports_fix property returns True."""
        linter = ESLintLinter()
        assert linter.supports_fix is True

    def test_get_version_success(self) -> None:
        """Test get_version with successful subprocess call."""
        linter = ESLintLinter()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "v8.56.0"

        with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
            with patch("subprocess.run", return_value=mock_result):
                version = linter.get_version()
                assert version == "8.56.0"

    def test_get_version_failure(self) -> None:
        """Test get_version returns unknown on failure."""
        linter = ESLintLinter()

        with patch.object(linter, "ensure_binary", side_effect=FileNotFoundError()):
            version = linter.get_version()
            assert version == "unknown"

    def test_ensure_binary_project_node_modules(self) -> None:
        """Test ensure_binary finds eslint in project node_modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create node_modules/.bin/eslint
            bin_dir = tmpdir_path / "node_modules" / ".bin"
            bin_dir.mkdir(parents=True)
            eslint_path = bin_dir / "eslint"
            eslint_path.touch()

            linter = ESLintLinter(project_root=tmpdir_path)
            binary = linter.ensure_binary()
            assert binary == eslint_path

    def test_ensure_binary_system_path(self) -> None:
        """Test ensure_binary finds eslint in system PATH."""
        linter = ESLintLinter()

        with patch("shutil.which", return_value="/usr/local/bin/eslint"):
            binary = linter.ensure_binary()
            assert binary == Path("/usr/local/bin/eslint")

    def test_ensure_binary_not_found(self) -> None:
        """Test ensure_binary raises when eslint not found."""
        linter = ESLintLinter()

        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError) as exc_info:
                linter.ensure_binary()
            assert "ESLint is not installed" in str(exc_info.value)

    def test_lint_no_binary(self) -> None:
        """Test lint returns empty when binary not found."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(linter, "ensure_binary", side_effect=FileNotFoundError("not found")):
                issues = linter.lint(context)
                assert issues == []

    def test_lint_success(self) -> None:
        """Test lint parses output correctly."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            eslint_output = json.dumps([
                {
                    "filePath": "/test/src/file.js",
                    "messages": [
                        {
                            "ruleId": "no-unused-vars",
                            "severity": 2,
                            "message": "'x' is assigned a value but never used.",
                            "line": 10,
                            "column": 5,
                            "endLine": 10,
                            "endColumn": 6,
                        }
                    ],
                    "errorCount": 1,
                    "warningCount": 0,
                }
            ])

            mock_result = make_completed_process(
                returncode=1,
                stdout=eslint_output,
            )

            with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
                with patch("lucidscan.plugins.linters.eslint.run_with_streaming", return_value=mock_result):
                    issues = linter.lint(context)

                    assert len(issues) == 1
                    assert issues[0].source_tool == "eslint"
                    assert issues[0].scanner == ToolDomain.LINTING
                    assert "no-unused-vars" in issues[0].title
                    assert issues[0].line_start == 10
                    assert issues[0].severity == Severity.HIGH

    def test_lint_timeout(self) -> None:
        """Test lint handles timeout."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
                with patch("lucidscan.plugins.linters.eslint.run_with_streaming",
                          side_effect=subprocess.TimeoutExpired("eslint", 120)):
                    issues = linter.lint(context)
                    assert issues == []

    def test_lint_subprocess_error(self) -> None:
        """Test lint handles subprocess error."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
                with patch("lucidscan.plugins.linters.eslint.run_with_streaming",
                          side_effect=OSError("command failed")):
                    issues = linter.lint(context)
                    assert issues == []

    def test_lint_uses_src_dir_when_no_paths(self) -> None:
        """Test lint uses src directory when no paths specified."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create src directory
            src_dir = tmpdir_path / "src"
            src_dir.mkdir()

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[],  # Empty paths
                enabled_domains=[],
            )

            mock_result = make_completed_process(returncode=0, stdout="[]")

            with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
                with patch("lucidscan.plugins.linters.eslint.run_with_streaming", return_value=mock_result) as mock_run:
                    linter.lint(context)
                    # Check that src was passed
                    call_args = mock_run.call_args
                    cmd = call_args.kwargs.get("cmd") or call_args[1].get("cmd") or call_args[0][0]
                    assert str(src_dir) in cmd


class TestESLintFix:
    """Tests for ESLint fix functionality."""

    def test_fix_no_binary(self) -> None:
        """Test fix returns empty result when binary not found."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            with patch.object(linter, "ensure_binary", side_effect=FileNotFoundError("not found")):
                result = linter.fix(context)
                assert result.issues_fixed == 0

    def test_fix_timeout(self) -> None:
        """Test fix handles timeout."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            mock_result = make_completed_process(returncode=0, stdout="[]")

            with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
                with patch("lucidscan.plugins.linters.eslint.run_with_streaming") as mock_run:
                    # First call (pre_issues lint) succeeds, second call (fix) times out
                    mock_run.side_effect = [
                        mock_result,
                        subprocess.TimeoutExpired("eslint", 120),
                    ]
                    result = linter.fix(context)
                    assert result.issues_fixed == 0

    def test_fix_success(self) -> None:
        """Test fix returns correct statistics."""
        linter = ESLintLinter()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            # Pre-fix: 2 issues
            pre_output = json.dumps([
                {
                    "filePath": "/test/file.js",
                    "messages": [
                        {"ruleId": "rule1", "severity": 2, "message": "Issue 1", "line": 1, "column": 1},
                        {"ruleId": "rule2", "severity": 2, "message": "Issue 2", "line": 2, "column": 1},
                    ],
                }
            ])

            # Post-fix: 1 issue remaining
            post_output = json.dumps([
                {
                    "filePath": "/test/file.js",
                    "messages": [
                        {"ruleId": "rule2", "severity": 2, "message": "Issue 2", "line": 2, "column": 1},
                    ],
                }
            ])

            pre_result = make_completed_process(returncode=1, stdout=pre_output)
            post_result = make_completed_process(returncode=1, stdout=post_output)

            with patch.object(linter, "ensure_binary", return_value=Path("/usr/bin/eslint")):
                with patch("lucidscan.plugins.linters.eslint.run_with_streaming") as mock_run:
                    mock_run.side_effect = [pre_result, post_result]
                    result = linter.fix(context)
                    assert result.issues_fixed == 1
                    assert result.issues_remaining == 1


class TestESLintOutputParsing:
    """Tests for ESLint output parsing."""

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        linter = ESLintLinter()
        issues = linter._parse_output("", Path("/project"))
        assert issues == []

    def test_parse_empty_json_array(self) -> None:
        """Test parsing empty JSON array."""
        linter = ESLintLinter()
        issues = linter._parse_output("[]", Path("/project"))
        assert issues == []

    def test_parse_invalid_json(self) -> None:
        """Test parsing invalid JSON."""
        linter = ESLintLinter()
        issues = linter._parse_output("not json", Path("/project"))
        assert issues == []

    def test_parse_single_file_single_issue(self) -> None:
        """Test parsing single file with single issue."""
        linter = ESLintLinter()
        output = json.dumps([
            {
                "filePath": "/test/file.js",
                "messages": [
                    {
                        "ruleId": "no-unused-vars",
                        "severity": 2,
                        "message": "'x' is not used.",
                        "line": 5,
                        "column": 3,
                    }
                ],
            }
        ])

        issues = linter._parse_output(output, Path("/project"))

        assert len(issues) == 1
        assert issues[0].line_start == 5
        assert "no-unused-vars" in issues[0].title

    def test_parse_multiple_files(self) -> None:
        """Test parsing multiple files."""
        linter = ESLintLinter()
        output = json.dumps([
            {
                "filePath": "/test/a.js",
                "messages": [
                    {"ruleId": "rule1", "severity": 2, "message": "Error 1", "line": 1, "column": 1}
                ],
            },
            {
                "filePath": "/test/b.js",
                "messages": [
                    {"ruleId": "rule2", "severity": 1, "message": "Warning 1", "line": 5, "column": 1}
                ],
            },
        ])

        issues = linter._parse_output(output, Path("/project"))

        assert len(issues) == 2

    def test_parse_file_with_no_messages(self) -> None:
        """Test parsing file with no messages."""
        linter = ESLintLinter()
        output = json.dumps([
            {
                "filePath": "/test/clean.js",
                "messages": [],
            }
        ])

        issues = linter._parse_output(output, Path("/project"))

        assert len(issues) == 0


class TestSeverityMapping:
    """Tests for ESLint severity mapping."""

    def test_severity_map_error(self) -> None:
        """Test that severity 2 maps to HIGH."""
        assert SEVERITY_MAP[2] == Severity.HIGH

    def test_severity_map_warning(self) -> None:
        """Test that severity 1 maps to MEDIUM."""
        assert SEVERITY_MAP[1] == Severity.MEDIUM

    def test_message_to_issue_error_severity(self) -> None:
        """Test message with error severity."""
        linter = ESLintLinter()
        message = {
            "ruleId": "test-rule",
            "severity": 2,
            "message": "Error message",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.severity == Severity.HIGH

    def test_message_to_issue_warning_severity(self) -> None:
        """Test message with warning severity."""
        linter = ESLintLinter()
        message = {
            "ruleId": "test-rule",
            "severity": 1,
            "message": "Warning message",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.severity == Severity.MEDIUM

    def test_message_to_issue_unknown_severity(self) -> None:
        """Test message with unknown severity defaults to MEDIUM."""
        linter = ESLintLinter()
        message = {
            "ruleId": "test-rule",
            "severity": 99,  # Unknown
            "message": "Message",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.severity == Severity.MEDIUM


class TestIssueIdGeneration:
    """Tests for issue ID generation."""

    def test_generate_issue_id_deterministic(self) -> None:
        """Test that issue IDs are deterministic."""
        linter = ESLintLinter()

        id1 = linter._generate_issue_id("no-unused-vars", "test.js", 10, 5, "Variable not used")
        id2 = linter._generate_issue_id("no-unused-vars", "test.js", 10, 5, "Variable not used")

        assert id1 == id2

    def test_generate_issue_id_different_inputs(self) -> None:
        """Test that different inputs produce different IDs."""
        linter = ESLintLinter()

        id1 = linter._generate_issue_id("rule1", "test.js", 10, 5, "Message")
        id2 = linter._generate_issue_id("rule2", "test.js", 10, 5, "Message")

        assert id1 != id2

    def test_generate_issue_id_with_rule(self) -> None:
        """Test issue ID format with rule."""
        linter = ESLintLinter()

        issue_id = linter._generate_issue_id("no-unused-vars", "test.js", 10, 5, "Message")

        assert issue_id.startswith("eslint-no-unused-vars-")

    def test_generate_issue_id_without_rule(self) -> None:
        """Test issue ID format without rule."""
        linter = ESLintLinter()

        issue_id = linter._generate_issue_id("", "test.js", 10, 5, "Message")

        assert issue_id.startswith("eslint-")
        assert "eslint--" not in issue_id  # Should not have double dash

    def test_generate_issue_id_handles_none_values(self) -> None:
        """Test issue ID handles None line/column."""
        linter = ESLintLinter()

        # Should not raise
        issue_id = linter._generate_issue_id("rule", "file.js", None, None, "Message")
        assert issue_id.startswith("eslint-rule-")


class TestMessageToIssue:
    """Tests for message to issue conversion."""

    def test_message_with_fix(self) -> None:
        """Test message with fix information."""
        linter = ESLintLinter()
        message = {
            "ruleId": "semi",
            "severity": 2,
            "message": "Missing semicolon.",
            "line": 1,
            "column": 10,
            "fix": {"range": [9, 9], "text": ";"},
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.scanner_metadata.get("fixable") is True

    def test_message_without_fix(self) -> None:
        """Test message without fix information."""
        linter = ESLintLinter()
        message = {
            "ruleId": "no-undef",
            "severity": 2,
            "message": "'x' is not defined.",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.scanner_metadata.get("fixable") is False

    def test_message_without_rule_id(self) -> None:
        """Test message without rule ID."""
        linter = ESLintLinter()
        message = {
            "severity": 2,
            "message": "Parsing error.",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.title == "Parsing error."

    def test_message_relative_path(self) -> None:
        """Test message with relative path."""
        linter = ESLintLinter()
        message = {
            "ruleId": "test",
            "severity": 2,
            "message": "Test",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "src/file.js", Path("/project"))

        assert issue is not None
        # Use Path for cross-platform comparison
        assert issue.file_path == Path("/project/src/file.js")

    def test_message_absolute_path(self) -> None:
        """Test message with absolute path."""
        linter = ESLintLinter()
        message = {
            "ruleId": "test",
            "severity": 2,
            "message": "Test",
            "line": 1,
            "column": 1,
        }

        issue = linter._message_to_issue(message, "/absolute/path/file.js", Path("/project"))

        assert issue is not None
        # Use Path for cross-platform comparison
        assert issue.file_path == Path("/absolute/path/file.js")

    def test_message_with_end_line(self) -> None:
        """Test message with end line."""
        linter = ESLintLinter()
        message = {
            "ruleId": "test",
            "severity": 2,
            "message": "Test",
            "line": 1,
            "column": 1,
            "endLine": 5,
            "endColumn": 10,
        }

        issue = linter._message_to_issue(message, "/test/file.js", Path("/project"))

        assert issue is not None
        assert issue.line_start == 1
        assert issue.line_end == 5
