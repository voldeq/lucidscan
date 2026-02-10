"""Tests for exclusion pattern handling across all scanner plugins.

This module tests that exclusion patterns configured in lucidshark.yml or
.lucidsharkignore are correctly applied to all scanning tools.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from lucidshark.config.ignore import IgnorePatterns
from lucidshark.core.models import ScanContext, ScanDomain, ToolDomain


class TestScanContextExcludePatterns:
    """Tests for ScanContext.get_exclude_patterns method."""

    def test_get_exclude_patterns_with_patterns(self) -> None:
        """Test that get_exclude_patterns returns patterns from IgnorePatterns."""
        ignore = IgnorePatterns(["*.log", "tests/**", ".venv/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        patterns = context.get_exclude_patterns()
        assert "*.log" in patterns
        assert "tests/**" in patterns
        assert ".venv/**" in patterns

    def test_get_exclude_patterns_without_patterns(self) -> None:
        """Test that get_exclude_patterns returns empty list when no patterns."""
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=None,
        )

        patterns = context.get_exclude_patterns()
        assert patterns == []


class TestRuffExclusionPatterns:
    """Tests for Ruff linter exclusion pattern handling."""

    def test_ruff_adds_exclude_flags(self) -> None:
        """Test that Ruff adds --extend-exclude flags for each pattern."""
        from lucidshark.plugins.linters.ruff import RuffLinter

        linter = RuffLinter()
        ignore = IgnorePatterns(["*.log", ".venv/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        with patch.object(linter, "ensure_binary", return_value=Path("/bin/ruff")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
                linter.lint(context)

                # Check the command arguments
                cmd = mock_run.call_args[0][0]
                assert "--extend-exclude" in cmd
                # Verify both patterns are added (simplified forms)
                exclude_indices = [i for i, x in enumerate(cmd) if x == "--extend-exclude"]
                assert len(exclude_indices) == 2

    def test_ruff_simplifies_glob_patterns_for_exclude(self) -> None:
        """Patterns like **/.venv/** are simplified to bare names for cross-platform reliability."""
        from lucidshark.plugins.linters.ruff import RuffLinter

        linter = RuffLinter()
        ignore = IgnorePatterns([
            "**/.venv/**",
            "**/node_modules/**",
            "**/__pycache__/**",
            "tests/integration/projects/**",
            "*.log",
        ])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        patterns = linter._get_ruff_exclude_patterns(context)
        # **/<name>/** stripped to bare name
        assert ".venv" in patterns
        assert "node_modules" in patterns
        assert "__pycache__" in patterns
        # <path>/** stripped trailing /**
        assert "tests/integration/projects" in patterns
        # Simple glob kept as-is
        assert "*.log" in patterns
        # No ** wrappers remain
        assert "**/.venv/**" not in patterns
        assert "**/node_modules/**" not in patterns

    def test_ruff_simplify_exclude_pattern_variants(self) -> None:
        """Test various pattern forms are simplified correctly."""
        from lucidshark.plugins.linters.ruff import RuffLinter

        simplify = RuffLinter._simplify_exclude_pattern
        # **/<name>/** → <name>
        assert simplify("**/.lucidshark/**") == ".lucidshark"
        # **/<name> → <name>
        assert simplify("**/build") == "build"
        # <path>/** → <path>
        assert simplify("docs/**") == "docs"
        # bare name stays as-is
        assert simplify(".venv") == ".venv"
        # simple glob stays as-is
        assert simplify("*.pyc") == "*.pyc"
        # backslashes normalized to forward slashes
        assert simplify("**\\.git\\**") == ".git"


class TestESLintExclusionPatterns:
    """Tests for ESLint linter exclusion pattern handling."""

    def test_eslint_adds_ignore_pattern_flags(self) -> None:
        """Test that ESLint adds --ignore-pattern flags for each pattern."""
        from lucidshark.plugins.linters.eslint import ESLintLinter

        linter = ESLintLinter()
        ignore = IgnorePatterns(["*.log", "node_modules/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        with patch.object(linter, "ensure_binary", return_value=Path("/bin/eslint")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
                linter.lint(context)

                cmd = mock_run.call_args[0][0]
                assert "--ignore-pattern" in cmd
                ignore_indices = [i for i, x in enumerate(cmd) if x == "--ignore-pattern"]
                assert len(ignore_indices) == 2


class TestMypyExclusionPatterns:
    """Tests for mypy type checker exclusion pattern handling."""

    def test_mypy_adds_exclude_flags(self) -> None:
        """Test that mypy adds --exclude flags for each pattern."""
        from lucidshark.plugins.type_checkers.mypy import MypyChecker

        checker = MypyChecker()
        ignore = IgnorePatterns(["tests/**", ".venv/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.TYPE_CHECKING],
            ignore_patterns=ignore,
        )

        with patch.object(checker, "ensure_binary", return_value=Path("/bin/mypy")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                checker.check(context)

                cmd = mock_run.call_args[0][0]
                assert "--exclude" in cmd
                exclude_indices = [i for i, x in enumerate(cmd) if x == "--exclude"]
                assert len(exclude_indices) == 2


class TestTrivyExclusionPatterns:
    """Tests for Trivy scanner exclusion pattern handling."""

    def test_trivy_splits_directory_patterns(self) -> None:
        """Test that Trivy uses --skip-dirs for directory patterns."""
        from lucidshark.plugins.scanners.trivy import TrivyScanner

        scanner = TrivyScanner()
        # Patterns ending with / or /** should be treated as directories
        ignore = IgnorePatterns([".venv/", "node_modules/**", "dist/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ScanDomain.SCA],
            ignore_patterns=ignore,
        )

        with patch.object(scanner, "ensure_binary", return_value=Path("/bin/trivy")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
                scanner.scan(context)

                cmd = mock_run.call_args[0][0]
                # Directory patterns should use --skip-dirs
                assert "--skip-dirs" in cmd
                skip_dirs_indices = [i for i, x in enumerate(cmd) if x == "--skip-dirs"]
                # All 3 patterns end with / or /** so should be skip-dirs
                assert len(skip_dirs_indices) == 3

    def test_trivy_uses_skip_files_for_file_patterns(self) -> None:
        """Test that Trivy uses --skip-files for file patterns."""
        from lucidshark.plugins.scanners.trivy import TrivyScanner

        scanner = TrivyScanner()
        # Patterns NOT ending with / or /** should be treated as files
        ignore = IgnorePatterns(["*.log", "test.py"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ScanDomain.SCA],
            ignore_patterns=ignore,
        )

        with patch.object(scanner, "ensure_binary", return_value=Path("/bin/trivy")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
                scanner.scan(context)

                cmd = mock_run.call_args[0][0]
                assert "--skip-files" in cmd
                skip_files_indices = [i for i, x in enumerate(cmd) if x == "--skip-files"]
                assert len(skip_files_indices) == 2


class TestOpengrepExclusionPatterns:
    """Tests for OpenGrep scanner exclusion pattern handling."""

    def test_opengrep_adds_exclude_flags(self) -> None:
        """Test that OpenGrep adds --exclude flags for each pattern."""
        from lucidshark.plugins.scanners.opengrep import OpenGrepScanner

        scanner = OpenGrepScanner()
        ignore = IgnorePatterns(["tests/**", ".venv/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ScanDomain.SAST],
            ignore_patterns=ignore,
        )

        with patch.object(scanner, "ensure_binary", return_value=Path("/bin/osemgrep")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
                scanner.scan(context)

                cmd = mock_run.call_args[0][0]
                assert "--exclude" in cmd
                exclude_indices = [i for i, x in enumerate(cmd) if x == "--exclude"]
                assert len(exclude_indices) == 2


class TestCheckovExclusionPatterns:
    """Tests for Checkov scanner exclusion pattern handling."""

    def test_checkov_adds_skip_path_flags(self) -> None:
        """Test that Checkov adds --skip-path flags with regex patterns."""
        from lucidshark.plugins.scanners.checkov import CheckovScanner

        scanner = CheckovScanner()
        ignore = IgnorePatterns([".venv/**", "tests/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ScanDomain.IAC],
            ignore_patterns=ignore,
        )

        with patch.object(scanner, "ensure_binary", return_value=Path("/bin/checkov")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
                scanner.scan(context)

                cmd = mock_run.call_args[0][0]
                assert "--skip-path" in cmd
                skip_path_indices = [i for i, x in enumerate(cmd) if x == "--skip-path"]
                assert len(skip_path_indices) == 2

    def test_checkov_converts_glob_to_regex(self) -> None:
        """Test that Checkov converts glob patterns to regex."""
        from lucidshark.plugins.scanners.checkov import _glob_to_regex

        # The .venv/** pattern should be converted to \.venv/.*
        assert _glob_to_regex(".venv/**") == r"\.venv/.*"
        # *.log should match any file ending with .log
        assert _glob_to_regex("*.log") == r"[^/]*\.log"


class TestCheckstyleExclusionPatterns:
    """Tests for Checkstyle linter exclusion pattern handling."""

    def test_checkstyle_filters_files_with_ignore_patterns(self, tmp_path: Path) -> None:
        """Test that Checkstyle uses IgnorePatterns.matches() to filter files."""
        from lucidshark.plugins.linters.checkstyle import CheckstyleLinter

        # Create test directory structure
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "Main.java").write_text("class Main {}")
        (src_dir / "Test.java").write_text("class Test {}")

        excluded_dir = tmp_path / "vendor"
        excluded_dir.mkdir()
        (excluded_dir / "Vendor.java").write_text("class Vendor {}")

        linter = CheckstyleLinter()
        ignore = IgnorePatterns(["vendor/**"])
        context = ScanContext(
            project_root=tmp_path,
            paths=[src_dir, excluded_dir],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        java_files = linter._find_java_files(context)

        # Should include src files but not vendor files
        java_file_names = [Path(f).name for f in java_files]
        assert "Main.java" in java_file_names
        assert "Test.java" in java_file_names
        assert "Vendor.java" not in java_file_names

    def test_checkstyle_respects_glob_patterns(self, tmp_path: Path) -> None:
        """Test that Checkstyle correctly matches gitignore glob patterns."""
        from lucidshark.plugins.linters.checkstyle import CheckstyleLinter

        # Create test directory structure with various files
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "Main.java").write_text("class Main {}")

        # Create a test directory that should be excluded
        test_dir = tmp_path / "src" / "test"
        test_dir.mkdir()
        (test_dir / "TestFile.java").write_text("class TestFile {}")

        # Create a generated directory
        gen_dir = tmp_path / "generated"
        gen_dir.mkdir()
        (gen_dir / "Generated.java").write_text("class Generated {}")

        linter = CheckstyleLinter()
        ignore = IgnorePatterns(["**/test/**", "generated/**"])
        context = ScanContext(
            project_root=tmp_path,
            paths=[src_dir, gen_dir],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        java_files = linter._find_java_files(context)

        java_file_names = [Path(f).name for f in java_files]
        assert "Main.java" in java_file_names
        assert "TestFile.java" not in java_file_names  # Should be excluded by **/test/**
        assert "Generated.java" not in java_file_names  # Should be excluded by generated/**

    def test_checkstyle_handles_no_ignore_patterns(self, tmp_path: Path) -> None:
        """Test that Checkstyle works when no ignore patterns are set."""
        from lucidshark.plugins.linters.checkstyle import CheckstyleLinter

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "Main.java").write_text("class Main {}")

        linter = CheckstyleLinter()
        context = ScanContext(
            project_root=tmp_path,
            paths=[src_dir],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=None,
        )

        java_files = linter._find_java_files(context)

        java_file_names = [Path(f).name for f in java_files]
        assert "Main.java" in java_file_names


class TestExclusionPatternEdgeCases:
    """Tests for edge cases in exclusion pattern handling."""

    def test_empty_patterns_list(self) -> None:
        """Test that empty patterns list works correctly."""
        ignore = IgnorePatterns([])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        patterns = context.get_exclude_patterns()
        assert patterns == []

    def test_patterns_with_comments_filtered(self) -> None:
        """Test that comment lines are filtered from patterns."""
        ignore = IgnorePatterns(["# Comment", "*.log", "  # Another comment"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        patterns = context.get_exclude_patterns()
        assert len(patterns) == 1
        assert "*.log" in patterns
        assert "# Comment" not in patterns

    def test_negation_patterns_preserved(self) -> None:
        """Test that negation patterns (!) are preserved for tools."""
        ignore = IgnorePatterns(["tests/**", "!tests/important.py"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=ignore,
        )

        patterns = context.get_exclude_patterns()
        assert "tests/**" in patterns
        assert "!tests/important.py" in patterns
