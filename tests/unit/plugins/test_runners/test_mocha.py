"""Unit tests for Mocha runner plugin."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidshark.core.models import Severity, ToolDomain
from lucidshark.plugins.test_runners.mocha import MochaRunner


class TestMochaRunner:
    """Tests for MochaRunner class."""

    def test_name(self) -> None:
        runner = MochaRunner()
        assert runner.name == "mocha"

    def test_languages(self) -> None:
        runner = MochaRunner()
        assert runner.languages == ["javascript", "typescript"]

    def test_domain(self) -> None:
        runner = MochaRunner()
        assert runner.domain == ToolDomain.TESTING


class TestMochaRunnerBinaryFinding:
    """Tests for binary finding logic."""

    def test_find_in_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            binary = runner.ensure_binary()
            assert binary == mocha_bin

    @patch("shutil.which")
    def test_find_in_system_path(self, mock_which: MagicMock) -> None:
        mock_which.return_value = "/usr/local/bin/mocha"
        runner = MochaRunner()
        binary = runner.ensure_binary()
        assert binary == Path("/usr/local/bin/mocha")

    @patch("shutil.which")
    def test_not_found_raises_error(self, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        runner = MochaRunner()
        with pytest.raises(FileNotFoundError) as exc:
            runner.ensure_binary()
        assert "Mocha is not installed" in str(exc.value)


class TestMochaGetVersion:
    """Tests for version detection."""

    def test_get_version_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            with patch(
                "lucidshark.plugins.test_runners.base.get_cli_version",
                return_value="10.7.3",
            ):
                version = runner.get_version()
                assert version == "10.7.3"

    @patch("shutil.which", return_value=None)
    def test_get_version_unknown_when_not_found(self, mock_which: MagicMock) -> None:
        runner = MochaRunner()
        version = runner.get_version()
        assert version == "unknown"


class TestMochaNycDetection:
    """Tests for NYC binary detection."""

    def test_find_nyc_in_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            nyc_bin = node_bin / "nyc"
            nyc_bin.touch()
            nyc_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            result = runner._find_nyc_binary()
            assert result == nyc_bin

    @patch("shutil.which", return_value=None)
    def test_nyc_not_found_returns_none(self, mock_which: MagicMock) -> None:
        runner = MochaRunner()
        result = runner._find_nyc_binary()
        assert result is None


class TestMochaConfigDetection:
    """Tests for Mocha configuration file detection."""

    def test_find_mocharc_yml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            config = project_root / ".mocharc.yml"
            config.write_text("spec: test/**/*.test.js\n")

            runner = MochaRunner()
            result = runner._find_mocha_config(project_root)
            assert result == config

    def test_find_mocharc_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            config = project_root / ".mocharc.json"
            config.write_text('{"spec": "test/**/*.test.js"}\n')

            runner = MochaRunner()
            result = runner._find_mocha_config(project_root)
            assert result == config

    def test_no_config_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            runner = MochaRunner()
            result = runner._find_mocha_config(project_root)
            assert result is None

    def test_prefers_yml_over_json(self) -> None:
        """Config files are checked in MOCHA_CONFIG_FILES order."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            yml_config = project_root / ".mocharc.yml"
            yml_config.write_text("spec: test/**/*.test.js\n")
            json_config = project_root / ".mocharc.json"
            json_config.write_text('{"spec": "test/**/*.test.js"}\n')

            runner = MochaRunner()
            result = runner._find_mocha_config(project_root)
            assert result == yml_config


class TestMochaRunTests:
    """Tests for test execution flow."""

    @patch("shutil.which", return_value=None)
    def test_run_tests_binary_not_found(self, mock_which: MagicMock) -> None:
        runner = MochaRunner()
        context = MagicMock()
        context.project_root = Path("/project")
        context.paths = []
        context.stream_handler = None

        result = runner.run_tests(context)
        assert result.passed == 0
        assert result.failed == 0

    def test_run_tests_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("mocha", 600),
            ):
                result = runner.run_tests(context)
                assert result.passed == 0
                context.record_skip.assert_called_once()

    def test_run_tests_general_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            with patch("subprocess.run", side_effect=OSError("cannot execute")):
                result = runner.run_tests(context)
                assert result.passed == 0
                context.record_skip.assert_called_once()

    def test_run_tests_includes_exit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            mock_result = MagicMock()
            mock_result.stdout = "{}"
            mock_result.stderr = ""
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result) as mock_run:
                runner.run_tests(context)
                cmd = mock_run.call_args[0][0]
                assert "--exit" in cmd

    def test_run_tests_includes_json_reporter(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            mock_result = MagicMock()
            mock_result.stdout = "{}"
            mock_result.stderr = ""
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result) as mock_run:
                runner.run_tests(context)
                cmd = mock_run.call_args[0][0]
                assert "--reporter" in cmd
                reporter_idx = cmd.index("--reporter")
                assert cmd[reporter_idx + 1] == "json"

    def test_run_tests_with_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = [Path("test/unit")]

            mock_result = MagicMock()
            mock_result.stdout = "{}"
            mock_result.stderr = ""
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result) as mock_run:
                runner.run_tests(context)
                cmd = mock_run.call_args[0][0]
                assert "test/unit" in cmd

    def test_run_tests_wraps_with_nyc_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)
            nyc_bin = node_bin / "nyc"
            nyc_bin.touch()
            nyc_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            mock_result = MagicMock()
            mock_result.stdout = "{}"
            mock_result.stderr = ""
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result) as mock_run:
                runner.run_tests(context)
                cmd = mock_run.call_args[0][0]
                # NYC should be the first command
                assert str(nyc_bin) == cmd[0]
                assert "--" in cmd
                # Mocha binary should come after --
                dash_idx = cmd.index("--")
                assert str(mocha_bin) == cmd[dash_idx + 1]

    def test_run_tests_without_nyc(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)
            # No nyc binary

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            mock_result = MagicMock()
            mock_result.stdout = "{}"
            mock_result.stderr = ""
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result) as mock_run:
                runner.run_tests(context)
                cmd = mock_run.call_args[0][0]
                # Mocha should be the first command (no NYC)
                assert str(mocha_bin) == cmd[0]
                assert "--" not in cmd

    def test_run_tests_parses_json_from_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            node_bin = project_root / "node_modules" / ".bin"
            node_bin.mkdir(parents=True)
            mocha_bin = node_bin / "mocha"
            mocha_bin.touch()
            mocha_bin.chmod(0o755)

            runner = MochaRunner(project_root=project_root)
            context = MagicMock()
            context.project_root = project_root
            context.paths = []

            mocha_output = json.dumps(
                {
                    "stats": {
                        "suites": 2,
                        "tests": 5,
                        "passes": 4,
                        "pending": 1,
                        "failures": 0,
                        "duration": 250,
                    },
                    "tests": [],
                    "pending": [],
                    "failures": [],
                    "passes": [],
                }
            )

            mock_result = MagicMock()
            mock_result.stdout = mocha_output
            mock_result.stderr = ""
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result):
                result = runner.run_tests(context)
                assert result.passed == 4
                assert result.failed == 0
                assert result.skipped == 1
                assert result.duration_ms == 250


class TestMochaReportProcessing:
    """Tests for Mocha report processing."""

    def test_process_report_all_passed(self) -> None:
        runner = MochaRunner()

        report = {
            "stats": {
                "suites": 3,
                "tests": 10,
                "passes": 10,
                "pending": 0,
                "failures": 0,
                "duration": 500,
            },
            "tests": [],
            "pending": [],
            "failures": [],
            "passes": [],
        }

        result = runner._process_mocha_report(report, Path("/project"))
        assert result.passed == 10
        assert result.failed == 0
        assert result.skipped == 0
        assert result.success is True
        assert len(result.issues) == 0
        assert result.duration_ms == 500

    def test_process_report_with_failures(self) -> None:
        runner = MochaRunner()

        report = {
            "stats": {
                "suites": 2,
                "tests": 5,
                "passes": 3,
                "pending": 0,
                "failures": 2,
                "duration": 300,
            },
            "tests": [],
            "pending": [],
            "failures": [
                {
                    "title": "should add numbers",
                    "fullTitle": "Calculator should add numbers",
                    "duration": 5,
                    "err": {
                        "message": "expected 3 to equal 4",
                        "stack": (
                            "AssertionError: expected 3 to equal 4\n"
                            "    at Context.<anonymous> "
                            "(test/calculator.test.js:10:20)"
                        ),
                    },
                },
                {
                    "title": "should subtract numbers",
                    "fullTitle": "Calculator should subtract numbers",
                    "duration": 3,
                    "err": {
                        "message": "expected 5 to equal 3",
                        "stack": (
                            "AssertionError: expected 5 to equal 3\n"
                            "    at Context.<anonymous> "
                            "(test/calculator.test.js:15:20)"
                        ),
                    },
                },
            ],
            "passes": [],
        }

        result = runner._process_mocha_report(report, Path("/project"))
        assert result.passed == 3
        assert result.failed == 2
        assert result.success is False
        assert len(result.issues) == 2

        issue = result.issues[0]
        assert "Calculator should add numbers" in issue.title
        assert "expected 3 to equal 4" in issue.title
        assert issue.source_tool == "mocha"
        assert issue.severity == Severity.HIGH
        assert issue.rule_id == "failed"
        assert issue.file_path == Path("/project/test/calculator.test.js")
        assert issue.line_start == 10

    def test_process_report_with_pending(self) -> None:
        runner = MochaRunner()

        report = {
            "stats": {
                "suites": 1,
                "tests": 5,
                "passes": 3,
                "pending": 2,
                "failures": 0,
                "duration": 100,
            },
            "tests": [],
            "pending": [],
            "failures": [],
            "passes": [],
        }

        result = runner._process_mocha_report(report, Path("/project"))
        assert result.passed == 3
        assert result.skipped == 2
        assert result.total == 5

    def test_process_report_empty_stats(self) -> None:
        runner = MochaRunner()

        report: dict[str, object] = {"stats": {}, "failures": []}
        result = runner._process_mocha_report(report, Path("/project"))
        assert result.passed == 0
        assert result.failed == 0
        assert result.skipped == 0

    def test_process_report_missing_stats(self) -> None:
        runner = MochaRunner()

        report: dict[str, object] = {"failures": []}
        result = runner._process_mocha_report(report, Path("/project"))
        assert result.passed == 0
        assert result.failed == 0


class TestMochaOutputParsing:
    """Tests for JSON output extraction and parsing."""

    def test_parse_clean_json(self) -> None:
        runner = MochaRunner()
        output = json.dumps(
            {
                "stats": {"passes": 5, "failures": 0, "pending": 0, "duration": 100},
                "failures": [],
            }
        )
        result = runner._parse_mocha_output(output, "", Path("/project"))
        assert result.passed == 5

    def test_parse_empty_output(self) -> None:
        runner = MochaRunner()
        result = runner._parse_mocha_output("", "", Path("/project"))
        assert result.passed == 0

    def test_parse_whitespace_only(self) -> None:
        runner = MochaRunner()
        result = runner._parse_mocha_output("   \n  ", "", Path("/project"))
        assert result.passed == 0

    def test_parse_invalid_json(self) -> None:
        runner = MochaRunner()
        result = runner._parse_mocha_output("not json at all", "", Path("/project"))
        assert result.passed == 0

    def test_parse_json_with_nyc_prefix(self) -> None:
        """When NYC wraps mocha, coverage text may precede JSON."""
        runner = MochaRunner()
        nyc_prefix = (
            "----------|---------|----------|---------|---------|---\n"
            "File      | % Stmts | % Branch | % Funcs | % Lines | Uncov\n"
            "----------|---------|----------|---------|---------|---\n"
            "All files |     100 |      100 |     100 |     100 |\n"
            "----------|---------|----------|---------|---------|---\n"
        )
        json_output = json.dumps(
            {
                "stats": {"passes": 3, "failures": 0, "pending": 0, "duration": 50},
                "failures": [],
            }
        )
        output = nyc_prefix + json_output
        result = runner._parse_mocha_output(output, "", Path("/project"))
        assert result.passed == 3

    def test_parse_json_with_nyc_suffix(self) -> None:
        """NYC coverage text may appear after JSON."""
        runner = MochaRunner()
        json_output = json.dumps(
            {
                "stats": {"passes": 2, "failures": 0, "pending": 0, "duration": 30},
                "failures": [],
            }
        )
        nyc_suffix = "\n----------|---------|----------|---------|---------|---\n"
        output = json_output + nyc_suffix
        result = runner._parse_mocha_output(output, "", Path("/project"))
        assert result.passed == 2


class TestMochaJsonExtraction:
    """Tests for JSON extraction from mixed output."""

    def test_extract_clean_json(self) -> None:
        runner = MochaRunner()
        data = '{"stats": {"passes": 1}}'
        result = runner._extract_json(data)
        assert result is not None
        assert json.loads(result)["stats"]["passes"] == 1

    def test_extract_json_with_prefix(self) -> None:
        runner = MochaRunner()
        data = 'some text before\n{"stats": {"passes": 2}}'
        result = runner._extract_json(data)
        assert result is not None
        assert json.loads(result)["stats"]["passes"] == 2

    def test_extract_no_json(self) -> None:
        runner = MochaRunner()
        result = runner._extract_json("no json here")
        assert result is None

    def test_extract_empty_string(self) -> None:
        runner = MochaRunner()
        result = runner._extract_json("")
        assert result is None

    def test_extract_only_open_brace(self) -> None:
        runner = MochaRunner()
        result = runner._extract_json("{broken")
        assert result is None

    def test_extract_json_with_surrounding_text(self) -> None:
        runner = MochaRunner()
        data = 'prefix text {"key": "value"} suffix text'
        result = runner._extract_json(data)
        assert result is not None
        assert json.loads(result)["key"] == "value"


class TestMochaFailureToIssue:
    """Tests for failure to issue conversion."""

    def test_basic_failure(self) -> None:
        runner = MochaRunner()

        failure = {
            "title": "should return 42",
            "fullTitle": "MyModule should return 42",
            "duration": 5,
            "err": {
                "message": "expected 41 to equal 42",
                "stack": (
                    "AssertionError: expected 41 to equal 42\n"
                    "    at Context.<anonymous> (test/mymodule.test.js:8:14)"
                ),
            },
        }

        issue = runner._failure_to_issue(failure, Path("/project"))
        assert issue is not None
        assert issue.domain == ToolDomain.TESTING
        assert issue.source_tool == "mocha"
        assert issue.severity == Severity.HIGH
        assert issue.rule_id == "failed"
        assert "MyModule should return 42" in issue.title
        assert issue.file_path == Path("/project/test/mymodule.test.js")
        assert issue.line_start == 8

    def test_failure_without_stack(self) -> None:
        runner = MochaRunner()

        failure = {
            "title": "should work",
            "fullTitle": "App should work",
            "err": {
                "message": "Test failed",
                "stack": "",
            },
        }

        issue = runner._failure_to_issue(failure, Path("/project"))
        assert issue is not None
        assert issue.file_path is None
        assert issue.line_start is None

    def test_failure_with_empty_err(self) -> None:
        runner = MochaRunner()

        failure = {
            "title": "should work",
            "fullTitle": "App should work",
            "err": {},
        }

        issue = runner._failure_to_issue(failure, Path("/project"))
        assert issue is not None
        assert "App should work" in issue.title
        assert "Test failed" in issue.title

    def test_failure_typescript_file(self) -> None:
        runner = MochaRunner()

        failure = {
            "title": "should compile",
            "fullTitle": "TS Module should compile",
            "err": {
                "message": "expected true to be false",
                "stack": (
                    "AssertionError: expected true to be false\n"
                    "    at Context.<anonymous> (test/module.spec.ts:22:10)"
                ),
            },
        }

        issue = runner._failure_to_issue(failure, Path("/project"))
        assert issue is not None
        assert issue.file_path == Path("/project/test/module.spec.ts")
        assert issue.line_start == 22

    def test_failure_relative_path(self) -> None:
        runner = MochaRunner()

        failure = {
            "title": "test",
            "fullTitle": "Suite test",
            "err": {
                "message": "fail",
                "stack": "    at Context.<anonymous> (test/app.test.js:5:1)",
            },
        }

        issue = runner._failure_to_issue(failure, Path("/myproject"))
        assert issue is not None
        assert issue.file_path == Path("/myproject/test/app.test.js")

    def test_failure_metadata_populated(self) -> None:
        runner = MochaRunner()

        failure = {
            "title": "should work",
            "fullTitle": "Suite should work",
            "err": {
                "message": "expected 1 to equal 2",
                "stack": "stack trace here",
            },
        }

        issue = runner._failure_to_issue(failure, Path("/project"))
        assert issue is not None
        assert issue.metadata["full_title"] == "Suite should work"
        assert issue.metadata["title"] == "should work"
        assert issue.metadata["error_message"] == "expected 1 to equal 2"
        assert issue.metadata["stack"] == "stack trace here"


class TestMochaLocationExtraction:
    """Tests for stack trace location extraction."""

    def test_parenthesized_test_file(self) -> None:
        runner = MochaRunner()
        stack = "    at Context.<anonymous> (test/app.test.js:10:20)"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/app.test.js")
        assert line == 10

    def test_parenthesized_spec_file(self) -> None:
        runner = MochaRunner()
        stack = "    at Context.<anonymous> (test/app.spec.ts:15:5)"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/app.spec.ts")
        assert line == 15

    def test_non_parenthesized(self) -> None:
        runner = MochaRunner()
        stack = "    at test/helper.js:42:10"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/helper.js")
        assert line == 42

    def test_absolute_path(self) -> None:
        runner = MochaRunner()
        stack = "    at Context.<anonymous> (/abs/path/test.spec.js:7:3)"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/abs/path/test.spec.js")
        assert line == 7

    def test_empty_stack(self) -> None:
        runner = MochaRunner()
        file_path, line = runner._extract_location("", Path("/project"))
        assert file_path is None
        assert line is None

    def test_no_location_in_stack(self) -> None:
        runner = MochaRunner()
        stack = "Error: something went wrong"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path is None
        assert line is None

    def test_jsx_file(self) -> None:
        runner = MochaRunner()
        stack = "    at Context.<anonymous> (test/component.test.jsx:30:5)"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/component.test.jsx")
        assert line == 30

    def test_tsx_file(self) -> None:
        runner = MochaRunner()
        stack = "    at Context.<anonymous> (test/component.spec.tsx:18:3)"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/component.spec.tsx")
        assert line == 18

    def test_mjs_file(self) -> None:
        runner = MochaRunner()
        stack = "    at Context.<anonymous> (test/module.test.mjs:12:5)"
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/module.test.mjs")
        assert line == 12

    def test_prefers_test_spec_file_in_multiline_stack(self) -> None:
        """Spec/test file patterns match before generic .js patterns."""
        runner = MochaRunner()
        stack = (
            "AssertionError: expected 1 to equal 2\n"
            "    at Assertion.fail (node_modules/chai/lib/chai.js:100:20)\n"
            "    at Context.<anonymous> (test/app.spec.js:10:20)\n"
        )
        file_path, line = runner._extract_location(stack, Path("/project"))
        assert file_path == Path("/project/test/app.spec.js")
        assert line == 10


class TestMochaAssertionExtraction:
    """Tests for assertion message extraction."""

    def test_chai_expected_pattern(self) -> None:
        runner = MochaRunner()
        result = runner._extract_assertion("expected 42 to equal 43")
        assert "expected 42 to equal 43" in result

    def test_expect_pattern(self) -> None:
        runner = MochaRunner()
        result = runner._extract_assertion("expect(received).to.equal(expected)")
        assert "expect" in result

    def test_assertion_error(self) -> None:
        runner = MochaRunner()
        result = runner._extract_assertion("AssertionError: values are not equal")
        assert "AssertionError" in result

    def test_empty_message(self) -> None:
        runner = MochaRunner()
        result = runner._extract_assertion("")
        assert result == ""

    def test_multiline_picks_first_meaningful(self) -> None:
        runner = MochaRunner()
        message = (
            "\n"
            "TypeError: Cannot read property 'foo' of undefined\n"
            "    at Context.<anonymous> (test.js:5:1)\n"
        )
        result = runner._extract_assertion(message)
        assert "TypeError" in result

    def test_skips_stack_trace_lines(self) -> None:
        runner = MochaRunner()
        message = "at Context.<anonymous>\nSome actual error message"
        result = runner._extract_assertion(message)
        assert "Some actual error message" in result

    def test_truncates_long_messages(self) -> None:
        runner = MochaRunner()
        long_msg = "expected " + "x" * 200 + " to equal y"
        result = runner._extract_assertion(long_msg)
        assert len(result) <= 100

    def test_expected_received_pattern(self) -> None:
        runner = MochaRunner()
        message = "Expected: 42\nReceived: 0"
        result = runner._extract_assertion(message)
        assert "Expected:" in result


class TestMochaIssueIdGeneration:
    """Tests for deterministic issue ID generation."""

    def test_same_input_same_id(self) -> None:
        runner = MochaRunner()
        id1 = runner._generate_issue_id("Suite test", "expected 1 to equal 2")
        id2 = runner._generate_issue_id("Suite test", "expected 1 to equal 2")
        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        runner = MochaRunner()
        id1 = runner._generate_issue_id("Suite test1", "assertion 1")
        id2 = runner._generate_issue_id("Suite test2", "assertion 2")
        assert id1 != id2

    def test_id_format(self) -> None:
        runner = MochaRunner()
        issue_id = runner._generate_issue_id("Suite test", "assertion")
        assert issue_id.startswith("mocha-")
        assert len(issue_id) == len("mocha-") + 12

    def test_id_is_deterministic(self) -> None:
        """IDs should be stable across runs."""
        runner1 = MochaRunner()
        runner2 = MochaRunner()
        id1 = runner1._generate_issue_id("Test", "err")
        id2 = runner2._generate_issue_id("Test", "err")
        assert id1 == id2


class TestMochaTestResultProperties:
    """Tests for TestResult properties with Mocha data."""

    def test_total_includes_all(self) -> None:
        runner = MochaRunner()
        report = {
            "stats": {
                "passes": 5,
                "failures": 2,
                "pending": 3,
                "duration": 100,
            },
            "failures": [],
        }
        result = runner._process_mocha_report(report, Path("/project"))
        assert result.total == 10  # 5 + 2 + 3

    def test_success_is_true_when_no_failures(self) -> None:
        runner = MochaRunner()
        report = {
            "stats": {"passes": 5, "failures": 0, "pending": 0, "duration": 100},
            "failures": [],
        }
        result = runner._process_mocha_report(report, Path("/project"))
        assert result.success is True

    def test_success_is_false_when_failures(self) -> None:
        runner = MochaRunner()
        report = {
            "stats": {"passes": 3, "failures": 2, "pending": 0, "duration": 100},
            "failures": [
                {
                    "title": "fail",
                    "fullTitle": "fail",
                    "err": {"message": "err", "stack": ""},
                },
                {
                    "title": "fail2",
                    "fullTitle": "fail2",
                    "err": {"message": "err2", "stack": ""},
                },
            ],
        }
        result = runner._process_mocha_report(report, Path("/project"))
        assert result.success is False
