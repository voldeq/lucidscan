"""Unit tests for PHPUnit Clover coverage plugin.

These tests use sample Clover XML to test the parsing logic without
requiring actual PHPUnit/Xdebug.
"""

from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

from lucidshark.core.models import ScanContext, ToolDomain
from lucidshark.plugins.coverage.phpunit_coverage import (
    PhpunitCoveragePlugin,
    CLOVER_PATHS,
)


class TestPhpunitCoveragePlugin:
    """Unit tests for PhpunitCoveragePlugin."""

    def test_name(self) -> None:
        plugin = PhpunitCoveragePlugin()
        assert plugin.name == "phpunit_coverage"

    def test_languages(self) -> None:
        plugin = PhpunitCoveragePlugin()
        assert plugin.languages == ["php"]

    def test_domain(self) -> None:
        plugin = PhpunitCoveragePlugin()
        assert plugin.domain == ToolDomain.COVERAGE


class TestCloverXmlParsing:
    """Tests for Clover XML parsing."""

    def test_parse_full_coverage(self) -> None:
        plugin = PhpunitCoveragePlugin()

        xml_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage generated="1234567890">
              <project timestamp="1234567890">
                <package name="App">
                  <file name="/app/src/Foo.php">
                    <line num="10" type="stmt" count="5"/>
                    <line num="11" type="stmt" count="3"/>
                    <line num="12" type="stmt" count="0"/>
                    <metrics loc="20" ncloc="15" classes="1" methods="2" coveredmethods="2"
                             conditionals="0" coveredconditionals="0"
                             statements="3" coveredstatements="2" elements="5" coveredelements="4"/>
                  </file>
                </package>
                <metrics files="1" loc="20" ncloc="15" classes="1" methods="2" coveredmethods="2"
                         conditionals="0" coveredconditionals="0"
                         statements="3" coveredstatements="2" elements="5" coveredelements="4"/>
              </project>
            </coverage>
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            clover_file = tmpdir_path / "coverage-clover.xml"
            clover_file.write_text(xml_content)

            result = plugin._parse_clover_xml(clover_file, tmpdir_path, threshold=80.0)

            assert result.tool == "phpunit_coverage"
            assert result.total_lines == 3
            assert result.covered_lines == 2
            assert result.missing_lines == 1
            # 66.7% < 80% threshold, so there should be a coverage issue
            assert len(result.issues) == 1
            assert result.issues[0].rule_id == "coverage_below_threshold"

    def test_parse_100_percent_coverage(self) -> None:
        plugin = PhpunitCoveragePlugin()

        xml_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage generated="1234567890">
              <project timestamp="1234567890">
                <package name="App">
                  <file name="/app/src/Foo.php">
                    <line num="10" type="stmt" count="5"/>
                    <line num="11" type="stmt" count="3"/>
                    <metrics statements="2" coveredstatements="2"/>
                  </file>
                </package>
                <metrics statements="2" coveredstatements="2"/>
              </project>
            </coverage>
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            clover_file = tmpdir_path / "coverage-clover.xml"
            clover_file.write_text(xml_content)

            result = plugin._parse_clover_xml(clover_file, tmpdir_path, threshold=80.0)

            assert result.percentage == 100.0
            assert len(result.issues) == 0

    def test_parse_missing_lines(self) -> None:
        plugin = PhpunitCoveragePlugin()

        xml_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage generated="1234567890">
              <project timestamp="1234567890">
                <package name="App">
                  <file name="/app/src/Bar.php">
                    <line num="5" type="stmt" count="1"/>
                    <line num="10" type="stmt" count="0"/>
                    <line num="15" type="stmt" count="0"/>
                    <line num="20" type="stmt" count="1"/>
                    <metrics statements="4" coveredstatements="2"/>
                  </file>
                </package>
                <metrics statements="4" coveredstatements="2"/>
              </project>
            </coverage>
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            clover_file = tmpdir_path / "coverage-clover.xml"
            clover_file.write_text(xml_content)

            result = plugin._parse_clover_xml(clover_file, tmpdir_path, threshold=80.0)

            # Check per-file missing lines
            assert len(result.files) == 1
            file_key = list(result.files.keys())[0]
            file_cov = result.files[file_key]
            assert file_cov.missing_lines == [10, 15]

    def test_parse_multiple_files(self) -> None:
        plugin = PhpunitCoveragePlugin()

        xml_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage generated="1234567890">
              <project timestamp="1234567890">
                <package name="App">
                  <file name="/app/src/Foo.php">
                    <line num="10" type="stmt" count="1"/>
                    <metrics statements="1" coveredstatements="1"/>
                  </file>
                  <file name="/app/src/Bar.php">
                    <line num="5" type="stmt" count="0"/>
                    <metrics statements="1" coveredstatements="0"/>
                  </file>
                </package>
                <metrics statements="2" coveredstatements="1"/>
              </project>
            </coverage>
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            clover_file = tmpdir_path / "coverage-clover.xml"
            clover_file.write_text(xml_content)

            result = plugin._parse_clover_xml(clover_file, tmpdir_path, threshold=80.0)

            assert len(result.files) == 2
            assert result.total_lines == 2
            assert result.covered_lines == 1

    def test_parse_invalid_xml(self) -> None:
        plugin = PhpunitCoveragePlugin()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            clover_file = tmpdir_path / "coverage-clover.xml"
            clover_file.write_text("not valid xml <<<<")

            result = plugin._parse_clover_xml(clover_file, tmpdir_path, threshold=80.0)

            assert result.total_lines == 0
            assert len(result.issues) == 1
            assert result.issues[0].rule_id == "no_coverage_data"


class TestMeasureCoverage:
    """Tests for measure_coverage method."""

    def test_no_clover_file(self) -> None:
        plugin = PhpunitCoveragePlugin()

        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(
                project_root=Path(tmpdir),
                paths=[Path(tmpdir)],
                enabled_domains=[],
            )

            result = plugin.measure_coverage(context, threshold=80.0)
            assert result.total_lines == 0
            assert len(result.issues) == 1
            assert result.issues[0].rule_id == "no_coverage_data"

    def test_finds_clover_file(self) -> None:
        plugin = PhpunitCoveragePlugin()

        xml_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage generated="1234567890">
              <project timestamp="1234567890">
                <metrics statements="10" coveredstatements="9"/>
              </project>
            </coverage>
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            clover_file = tmpdir_path / "coverage-clover.xml"
            clover_file.write_text(xml_content)

            context = ScanContext(
                project_root=tmpdir_path,
                paths=[tmpdir_path],
                enabled_domains=[],
            )

            result = plugin.measure_coverage(context, threshold=80.0)
            assert result.total_lines == 10
            assert result.covered_lines == 9
            assert result.percentage == 90.0
            assert len(result.issues) == 0  # 90% > 80% threshold


class TestFindCloverFile:
    """Tests for _find_clover_file."""

    def test_finds_coverage_clover_xml(self) -> None:
        plugin = PhpunitCoveragePlugin()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "coverage-clover.xml").touch()
            result = plugin._find_clover_file(tmpdir_path)
            assert result is not None
            assert result.name == "coverage-clover.xml"

    def test_finds_build_logs_clover(self) -> None:
        plugin = PhpunitCoveragePlugin()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "build" / "logs").mkdir(parents=True)
            (tmpdir_path / "build" / "logs" / "clover.xml").touch()
            result = plugin._find_clover_file(tmpdir_path)
            assert result is not None

    def test_returns_none_when_missing(self) -> None:
        plugin = PhpunitCoveragePlugin()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = plugin._find_clover_file(Path(tmpdir))
            assert result is None


class TestCloverPaths:
    """Tests for CLOVER_PATHS constant."""

    def test_standard_paths(self) -> None:
        assert "coverage-clover.xml" in CLOVER_PATHS
        assert "coverage.xml" in CLOVER_PATHS
        assert "build/logs/clover.xml" in CLOVER_PATHS
        assert "clover.xml" in CLOVER_PATHS
