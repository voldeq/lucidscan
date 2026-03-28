"""Unit tests for CTest test runner plugin."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lucidshark.core.models import ScanContext, Severity, ToolDomain
from lucidshark.plugins.test_runners.ctest import CTestRunner


FAKE_BINARY = Path("/usr/bin/ctest")


def _make_context(
    project_root: Path,
    enabled_domains: list | None = None,
) -> ScanContext:
    """Create a minimal ScanContext for testing."""
    return ScanContext(
        project_root=project_root,
        paths=[project_root],
        enabled_domains=enabled_domains or [],
    )


# ---------------------------------------------------------------------------
# CTestRunner properties
# ---------------------------------------------------------------------------


class TestCTestRunnerProperties:
    """Tests for CTestRunner basic properties."""

    def test_name(self) -> None:
        """Test plugin name."""
        runner = CTestRunner()
        assert runner.name == "ctest"

    def test_languages(self) -> None:
        """Test supported languages."""
        runner = CTestRunner()
        assert runner.languages == ["c"]

    def test_domain(self) -> None:
        """Test domain is TESTING."""
        runner = CTestRunner()
        assert runner.domain == ToolDomain.TESTING

    def test_init_with_project_root(self) -> None:
        """Test initialization with project root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CTestRunner(project_root=Path(tmpdir))
            assert runner._project_root == Path(tmpdir)

    def test_get_version(self) -> None:
        """Test get_version delegates to get_ctest_version."""
        runner = CTestRunner()
        with patch(
            "lucidshark.plugins.test_runners.ctest.get_ctest_version",
            return_value="ctest version 3.28.1",
        ):
            version = runner.get_version()
            assert version == "ctest version 3.28.1"

    def test_ensure_binary(self) -> None:
        """Test ensure_binary delegates to find_ctest."""
        runner = CTestRunner()
        with patch(
            "lucidshark.plugins.test_runners.ctest.find_ctest",
            return_value=FAKE_BINARY,
        ):
            binary = runner.ensure_binary()
            assert binary == FAKE_BINARY

    def test_ensure_binary_raises_when_not_found(self) -> None:
        """Test ensure_binary raises FileNotFoundError."""
        runner = CTestRunner()
        with patch(
            "lucidshark.plugins.test_runners.ctest.find_ctest",
            side_effect=FileNotFoundError("not found"),
        ):
            with pytest.raises(FileNotFoundError):
                runner.ensure_binary()


# ---------------------------------------------------------------------------
# _parse_text_output
# ---------------------------------------------------------------------------


class TestParseTextOutput:
    """Tests for _parse_text_output."""

    def test_parse_all_passing(self) -> None:
        """Test parsing output where all tests pass."""
        runner = CTestRunner()
        output = (
            "Test project /path/to/build\n"
            "    Start 1: test_math\n"
            "1/3 Test #1: test_math ......................   Passed    0.01 sec\n"
            "    Start 2: test_string\n"
            "2/3 Test #2: test_string ....................   Passed    0.02 sec\n"
            "    Start 3: test_io\n"
            "3/3 Test #3: test_io ........................   Passed    0.03 sec\n"
            "\n"
            "100% tests passed, 0 tests failed out of 3\n"
        )
        result = runner._parse_text_output(output, Path("/tmp"))
        assert result.passed == 3
        assert result.failed == 0
        assert result.skipped == 0
        assert result.tool == "ctest"

    def test_parse_with_failures(self) -> None:
        """Test parsing output with test failures."""
        runner = CTestRunner()
        output = (
            "Test project /path/to/build\n"
            "    Start 1: test_ok\n"
            "1/2 Test #1: test_ok ........................   Passed    0.01 sec\n"
            "    Start 2: test_bad\n"
            "2/2 Test #2: test_bad .......................***Failed    0.02 sec\n"
            "\n"
            "50% tests passed, 1 tests failed out of 2\n"
        )
        result = runner._parse_text_output(output, Path("/tmp"))
        assert result.passed == 1
        assert result.failed == 1
        assert len(result.issues) == 1
        assert result.issues[0].domain == ToolDomain.TESTING
        assert result.issues[0].source_tool == "ctest"
        assert result.issues[0].severity == Severity.HIGH
        assert "test_bad" in result.issues[0].title

    def test_parse_with_skipped(self) -> None:
        """Test parsing output with skipped tests."""
        runner = CTestRunner()
        output = (
            "Test project /path/to/build\n"
            "    Start 1: test_ok\n"
            "1/2 Test #1: test_ok ........................   Passed    0.01 sec\n"
            "    Start 2: test_skip\n"
            "2/2 Test #2: test_skip ......................***Not Run   0.00 sec\n"
        )
        result = runner._parse_text_output(output, Path("/tmp"))
        assert result.passed == 1
        assert result.skipped == 1

    def test_parse_empty_output(self) -> None:
        """Test parsing empty output."""
        runner = CTestRunner()
        result = runner._parse_text_output("", Path("/tmp"))
        assert result.passed == 0
        assert result.failed == 0
        assert result.skipped == 0

    def test_parse_duration_accumulation(self) -> None:
        """Test that durations are accumulated correctly."""
        runner = CTestRunner()
        output = (
            "1/2 Test #1: test_a .........................   Passed    1.50 sec\n"
            "2/2 Test #2: test_b .........................   Passed    2.50 sec\n"
        )
        result = runner._parse_text_output(output, Path("/tmp"))
        assert result.passed == 2
        assert result.duration_ms == 4000  # 1500 + 2500

    def test_failure_issue_has_metadata(self) -> None:
        """Test that failure issues contain test_name and outcome metadata."""
        runner = CTestRunner()
        output = "1/1 Test #1: test_bad .......................***Failed    0.02 sec\n"
        result = runner._parse_text_output(output, Path("/tmp"))
        assert len(result.issues) == 1
        assert result.issues[0].metadata["test_name"] == "test_bad"
        assert result.issues[0].metadata["outcome"] == "failed"


# ---------------------------------------------------------------------------
# _generate_ctest_issue_id
# ---------------------------------------------------------------------------


class TestGenerateCtestIssueId:
    """Tests for _generate_ctest_issue_id."""

    def test_deterministic(self) -> None:
        """Same test name produces the same ID."""
        runner = CTestRunner()
        id1 = runner._generate_ctest_issue_id("test_math")
        id2 = runner._generate_ctest_issue_id("test_math")
        assert id1 == id2

    def test_different_names_different_ids(self) -> None:
        """Different test names produce different IDs."""
        runner = CTestRunner()
        id1 = runner._generate_ctest_issue_id("test_a")
        id2 = runner._generate_ctest_issue_id("test_b")
        assert id1 != id2

    def test_format(self) -> None:
        """ID matches 'ctest-{12 hex chars}' pattern."""
        runner = CTestRunner()
        issue_id = runner._generate_ctest_issue_id("test_math")
        import re

        assert re.fullmatch(r"ctest-[0-9a-f]{12}", issue_id)

    def test_correct_hash(self) -> None:
        """Verify the hash computation is correct."""
        runner = CTestRunner()
        test_name = "test_example"
        content = f"ctest::{test_name}"
        expected_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        expected_id = f"ctest-{expected_hash}"
        assert runner._generate_ctest_issue_id(test_name) == expected_id


# ---------------------------------------------------------------------------
# _try_parse_xml
# ---------------------------------------------------------------------------


class TestTryParseXml:
    """Tests for _try_parse_xml."""

    def test_returns_none_when_no_testing_dir(self, tmp_path: Path) -> None:
        """Return None when Testing directory doesn't exist."""
        runner = CTestRunner()
        assert runner._try_parse_xml(tmp_path, tmp_path) is None

    def test_returns_none_when_no_tag_file(self, tmp_path: Path) -> None:
        """Return None when TAG file doesn't exist."""
        runner = CTestRunner()
        testing_dir = tmp_path / "Testing"
        testing_dir.mkdir()
        assert runner._try_parse_xml(tmp_path, tmp_path) is None

    def test_returns_none_when_tag_file_empty(self, tmp_path: Path) -> None:
        """Return None when TAG file is empty."""
        runner = CTestRunner()
        testing_dir = tmp_path / "Testing"
        testing_dir.mkdir()
        (testing_dir / "TAG").write_text("")
        assert runner._try_parse_xml(tmp_path, tmp_path) is None

    def test_returns_none_when_xml_not_found(self, tmp_path: Path) -> None:
        """Return None when Test.xml is not found in tagged directory."""
        runner = CTestRunner()
        testing_dir = tmp_path / "Testing"
        testing_dir.mkdir()
        (testing_dir / "TAG").write_text("20240101-1200\nExperimental\n")
        tagged_dir = testing_dir / "20240101-1200"
        tagged_dir.mkdir()
        # No Test.xml
        assert runner._try_parse_xml(tmp_path, tmp_path) is None


# ---------------------------------------------------------------------------
# _parse_ctest_xml
# ---------------------------------------------------------------------------


class TestParseCtestXml:
    """Tests for _parse_ctest_xml."""

    def test_parse_passing_tests(self, tmp_path: Path) -> None:
        """Test parsing XML with passing tests."""
        runner = CTestRunner()
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Site>
  <Testing>
    <Test Status="passed">
      <Name>test_math</Name>
    </Test>
    <Test Status="passed">
      <Name>test_string</Name>
    </Test>
    <ElapsedMinutes>0.5</ElapsedMinutes>
  </Testing>
</Site>"""
        xml_file = tmp_path / "Test.xml"
        xml_file.write_text(xml_content)

        result = runner._parse_ctest_xml(xml_file, tmp_path)
        assert result.passed == 2
        assert result.failed == 0
        assert result.tool == "ctest"
        assert result.duration_ms == 30000  # 0.5 * 60 * 1000

    def test_parse_failed_tests(self, tmp_path: Path) -> None:
        """Test parsing XML with failed tests."""
        runner = CTestRunner()
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Site>
  <Testing>
    <Test Status="passed">
      <Name>test_ok</Name>
    </Test>
    <Test Status="failed">
      <Name>test_bad</Name>
      <Results>
        <Measurement>
          <Value>assertion failed at line 42</Value>
        </Measurement>
      </Results>
    </Test>
  </Testing>
</Site>"""
        xml_file = tmp_path / "Test.xml"
        xml_file.write_text(xml_content)

        result = runner._parse_ctest_xml(xml_file, tmp_path)
        assert result.passed == 1
        assert result.failed == 1
        assert len(result.issues) == 1
        assert "test_bad" in result.issues[0].title

    def test_parse_skipped_tests(self, tmp_path: Path) -> None:
        """Test parsing XML with notrun tests."""
        runner = CTestRunner()
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Site>
  <Testing>
    <Test Status="notrun">
      <Name>test_skip</Name>
    </Test>
  </Testing>
</Site>"""
        xml_file = tmp_path / "Test.xml"
        xml_file.write_text(xml_content)

        result = runner._parse_ctest_xml(xml_file, tmp_path)
        assert result.passed == 0
        assert result.skipped == 1

    def test_parse_invalid_xml(self, tmp_path: Path) -> None:
        """Test parsing invalid XML returns empty result."""
        runner = CTestRunner()
        xml_file = tmp_path / "Test.xml"
        xml_file.write_text("not valid xml <<<<")

        result = runner._parse_ctest_xml(xml_file, tmp_path)
        assert result.passed == 0
        assert result.failed == 0


# ---------------------------------------------------------------------------
# run_tests
# ---------------------------------------------------------------------------


class TestRunTests:
    """Tests for run_tests method."""

    def test_binary_not_found(self) -> None:
        """Test run_tests returns empty result when binary not found."""
        runner = CTestRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = _make_context(Path(tmpdir))

            with patch.object(
                runner, "ensure_binary", side_effect=FileNotFoundError("not found")
            ):
                result = runner.run_tests(context)
                assert result.tool == "ctest"
                assert result.passed == 0
                assert result.failed == 0

    def test_no_build_dir(self) -> None:
        """Test run_tests skips when no build directory found."""
        runner = CTestRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = _make_context(Path(tmpdir))

            with patch.object(runner, "ensure_binary", return_value=FAKE_BINARY):
                result = runner.run_tests(context)
                assert result.tool == "ctest"
                assert result.passed == 0

    def test_run_tests_with_text_output(self) -> None:
        """Test run_tests falls back to text output parsing."""
        runner = CTestRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create build dir with CMakeCache.txt
            build_dir = tmpdir_path / "build"
            build_dir.mkdir()
            (build_dir / "CMakeCache.txt").touch()

            context = _make_context(tmpdir_path)

            stdout_output = (
                "Test project /path/to/build\n"
                "    Start 1: test_ok\n"
                "1/1 Test #1: test_ok ........................   Passed    0.01 sec\n"
                "\n"
                "100% tests passed, 0 tests failed out of 1\n"
            )

            mock_proc = MagicMock()
            mock_proc.stdout = stdout_output
            mock_proc.stderr = ""
            mock_proc.returncode = 0

            with (
                patch.object(runner, "ensure_binary", return_value=FAKE_BINARY),
                patch.object(
                    runner, "_run_test_subprocess", return_value=mock_proc
                ),
            ):
                result = runner.run_tests(context)
                assert result.passed == 1
                assert result.failed == 0

    def test_run_tests_with_xml_output(self) -> None:
        """Test run_tests parses XML output when available."""
        runner = CTestRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create build dir with CMakeCache.txt
            build_dir = tmpdir_path / "build"
            build_dir.mkdir()
            (build_dir / "CMakeCache.txt").touch()

            # Create Testing/TAG and Test.xml
            testing_dir = build_dir / "Testing"
            testing_dir.mkdir()
            (testing_dir / "TAG").write_text("20240101-1200\nExperimental\n")
            tagged_dir = testing_dir / "20240101-1200"
            tagged_dir.mkdir()
            xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Site>
  <Testing>
    <Test Status="passed">
      <Name>test_xml</Name>
    </Test>
    <Test Status="failed">
      <Name>test_xml_fail</Name>
    </Test>
  </Testing>
</Site>"""
            (tagged_dir / "Test.xml").write_text(xml_content)

            context = _make_context(tmpdir_path)

            mock_proc = MagicMock()
            mock_proc.stdout = ""
            mock_proc.stderr = ""
            mock_proc.returncode = 0

            with (
                patch.object(runner, "ensure_binary", return_value=FAKE_BINARY),
                patch.object(
                    runner, "_run_test_subprocess", return_value=mock_proc
                ),
            ):
                result = runner.run_tests(context)
                assert result.passed == 1
                assert result.failed == 1

    def test_run_tests_subprocess_returns_none(self) -> None:
        """Test run_tests handles None from subprocess (timeout/error)."""
        runner = CTestRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            build_dir = tmpdir_path / "build"
            build_dir.mkdir()
            (build_dir / "CMakeCache.txt").touch()

            context = _make_context(tmpdir_path)

            with (
                patch.object(runner, "ensure_binary", return_value=FAKE_BINARY),
                patch.object(
                    runner, "_run_test_subprocess", return_value=None
                ),
            ):
                result = runner.run_tests(context)
                assert result.tool == "ctest"
                assert result.passed == 0

    def test_run_tests_stderr_produces_build_failure_issue(self) -> None:
        """Test that stderr with no test results creates a build failure issue."""
        runner = CTestRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            build_dir = tmpdir_path / "build"
            build_dir.mkdir()
            (build_dir / "CMakeCache.txt").touch()

            context = _make_context(tmpdir_path)

            mock_proc = MagicMock()
            mock_proc.stdout = ""
            mock_proc.stderr = "CMake Error: some build failure"
            mock_proc.returncode = 1

            with (
                patch.object(runner, "ensure_binary", return_value=FAKE_BINARY),
                patch.object(
                    runner, "_run_test_subprocess", return_value=mock_proc
                ),
            ):
                result = runner.run_tests(context)
                assert result.errors == 1
                assert len(result.issues) == 1
                assert result.issues[0].id == "ctest-build-failure"
                assert result.issues[0].severity == Severity.HIGH
