"""Tests for template-based configuration composer."""

from __future__ import annotations

from pathlib import Path

import yaml

from lucidshark.detection.detector import ProjectContext
from lucidshark.detection.languages import LanguageInfo
from lucidshark.generation.template_composer import (
    LANGUAGE_TEMPLATE_MAP,
    TemplateComposer,
    load_template,
    merge_templates,
)


class TestLoadTemplate:
    """Tests for loading individual language templates."""

    def test_load_python_template(self) -> None:
        """Verify python.yml loads and has all expected domains."""
        template = load_template("python")
        assert template is not None
        pipeline = template["pipeline"]
        assert "linting" in pipeline
        assert "formatting" in pipeline
        assert "type_checking" in pipeline
        assert "security" in pipeline
        assert "testing" in pipeline
        assert "coverage" in pipeline
        assert "duplication" in pipeline

    def test_load_go_template_includes_gosec(self) -> None:
        """Verify go.yml includes gosec in security tools."""
        template = load_template("go")
        assert template is not None
        security_tools = template["pipeline"]["security"]["tools"]
        tool_names = [t["name"] for t in security_tools]
        assert "gosec" in tool_names

    def test_load_cpp_template_via_language_name(self) -> None:
        """Verify c++ maps to cpp.yml correctly."""
        template = load_template("c++")
        assert template is not None
        linting_tools = template["pipeline"]["linting"]["tools"]
        assert linting_tools[0]["name"] == "clang_tidy"

    def test_load_unknown_language_returns_none(self) -> None:
        """Verify unknown language returns None gracefully."""
        template = load_template("brainfuck")
        assert template is None

    def test_all_templates_load_successfully(self) -> None:
        """Every language in the map has a loadable template."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None, f"Failed to load template for '{language}'"

    def test_python_template_has_ruff_linter(self) -> None:
        """Python template uses ruff for linting."""
        template = load_template("python")
        assert template is not None
        tools = template["pipeline"]["linting"]["tools"]
        assert tools[0]["name"] == "ruff"

    def test_java_template_has_no_formatting(self) -> None:
        """Java template omits formatting (no Java formatter plugin)."""
        template = load_template("java")
        assert template is not None
        assert "formatting" not in template["pipeline"]


class TestMergeTemplates:
    """Tests for merging multiple language templates."""

    def test_single_language_passthrough(self) -> None:
        """Single language template passes through unchanged."""
        template = load_template("python")
        assert template is not None
        merged = merge_templates([template])
        assert merged["pipeline"]["linting"]["tools"][0]["name"] == "ruff"

    def test_merge_python_and_typescript(self) -> None:
        """Merge two languages: tools are unioned, exclude patterns merged."""
        py = load_template("python")
        ts = load_template("typescript")
        assert py is not None and ts is not None
        merged = merge_templates([py, ts])

        # Linting should have both ruff and eslint/biome
        linting_tools = [t["name"] for t in merged["pipeline"]["linting"]["tools"]]
        assert "ruff" in linting_tools
        assert "eslint" in linting_tools

        # Type checking should have mypy, pyright, and typescript
        tc_tools = [t["name"] for t in merged["pipeline"]["type_checking"]["tools"]]
        assert "mypy" in tc_tools
        assert "typescript" in tc_tools

        # Ignore patterns should include both Python and TS patterns
        exclude = merged["exclude"]
        assert "**/__pycache__/**" in exclude
        assert "**/node_modules/**" in exclude

    def test_security_tools_deduplicated(self) -> None:
        """trivy/opengrep/checkov appear once even from two templates."""
        py = load_template("python")
        ts = load_template("typescript")
        assert py is not None and ts is not None
        merged = merge_templates([py, ts])

        security_tools = merged["pipeline"]["security"]["tools"]
        trivy_count = sum(1 for t in security_tools if t["name"] == "trivy")
        opengrep_count = sum(1 for t in security_tools if t["name"] == "opengrep")
        assert trivy_count == 1, f"trivy appears {trivy_count} times"
        assert opengrep_count == 1, f"opengrep appears {opengrep_count} times"

    def test_duplo_not_duplicated(self) -> None:
        """duplo appears once in duplication domain."""
        py = load_template("python")
        go = load_template("go")
        assert py is not None and go is not None
        merged = merge_templates([py, go])

        dup_tools = merged["pipeline"]["duplication"]["tools"]
        duplo_count = sum(1 for t in dup_tools if t["name"] == "duplo")
        assert duplo_count == 1

    def test_merge_preserves_security_tool_domains(self) -> None:
        """Tool-level config (domains) preserved during merge."""
        go = load_template("go")
        assert go is not None
        merged = merge_templates([go])

        security_tools = merged["pipeline"]["security"]["tools"]
        trivy = next(t for t in security_tools if t["name"] == "trivy")
        assert "sca" in trivy["domains"]

    def test_merge_coverage_threshold_from_first(self) -> None:
        """Coverage threshold comes from first template."""
        py = load_template("python")
        ts = load_template("typescript")
        assert py is not None and ts is not None
        merged = merge_templates([py, ts])
        assert merged["pipeline"]["coverage"]["threshold"] == 80

    def test_merge_adds_domain_from_second_template(self) -> None:
        """If first template has no formatting but second does, it's added."""
        java = load_template("java")
        kotlin = load_template("kotlin")
        assert java is not None and kotlin is not None
        merged = merge_templates([java, kotlin])

        # Java has no formatting, but Kotlin has ktlint_format
        assert "formatting" in merged["pipeline"]
        fmt_tools = [t["name"] for t in merged["pipeline"]["formatting"]["tools"]]
        assert "ktlint_format" in fmt_tools

    def test_merge_empty_list_returns_empty(self) -> None:
        """Merging empty template list returns empty structure."""
        merged = merge_templates([])
        assert merged == {"pipeline": {}, "fail_on": {}, "exclude": []}


class TestTemplateComposer:
    """Tests for the TemplateComposer end-to-end."""

    def _make_context(
        self,
        tmp_path: Path,
        languages: list[str],
    ) -> ProjectContext:
        """Helper to create a ProjectContext."""
        return ProjectContext(
            root=tmp_path,
            languages=[LanguageInfo(name=lang, file_count=10) for lang in languages],
        )

    def test_compose_python_project(self, tmp_path: Path) -> None:
        """Full compose for a Python-only project."""
        context = self._make_context(tmp_path, ["python"])
        composer = TemplateComposer()
        config = composer.compose_config(context)

        assert config["version"] == 1
        assert config["project"]["languages"] == ["python"]
        assert config["pipeline"]["linting"]["tools"][0]["name"] == "ruff"

    def test_compose_multi_language_project(self, tmp_path: Path) -> None:
        """Full compose for Python + TypeScript project."""
        context = self._make_context(tmp_path, ["python", "typescript"])
        composer = TemplateComposer()
        config = composer.compose_config(context)

        assert "python" in config["project"]["languages"]
        assert "typescript" in config["project"]["languages"]

        # Should have tools from both languages
        linting_tools = [t["name"] for t in config["pipeline"]["linting"]["tools"]]
        assert "ruff" in linting_tools
        assert "eslint" in linting_tools

    def test_compose_no_languages_detected(self, tmp_path: Path) -> None:
        """Empty languages list produces minimal config."""
        context = self._make_context(tmp_path, [])
        composer = TemplateComposer()
        config = composer.compose_config(context)

        assert config["version"] == 1
        assert config["project"]["languages"] == []
        # Pipeline should not be present (no templates to load)
        assert "pipeline" not in config

    def test_compose_skips_unknown_languages(self, tmp_path: Path) -> None:
        """Unknown languages are listed in project but don't add tools."""
        context = self._make_context(tmp_path, ["python", "brainfuck"])
        composer = TemplateComposer()
        config = composer.compose_config(context)

        # brainfuck in project.languages but no pipeline additions from it
        assert "python" in config["project"]["languages"]
        assert "brainfuck" in config["project"]["languages"]
        # Should still have python tools
        linting_tools = [t["name"] for t in config["pipeline"]["linting"]["tools"]]
        assert "ruff" in linting_tools

    def test_write_creates_file(self, tmp_path: Path) -> None:
        """write() creates lucidshark.yml on disk."""
        context = self._make_context(tmp_path, ["python"])
        composer = TemplateComposer()
        output_path = composer.write(context)

        assert output_path.exists()
        assert output_path.name == "lucidshark.yml"

        # Verify it's valid YAML
        content = output_path.read_text()
        config = yaml.safe_load(content)
        assert config["version"] == 1

    def test_write_to_custom_path(self, tmp_path: Path) -> None:
        """write() respects custom output path."""
        context = self._make_context(tmp_path, ["go"])
        composer = TemplateComposer()
        custom_path = tmp_path / "custom.yml"
        output_path = composer.write(context, output_path=custom_path)

        assert output_path == custom_path
        assert custom_path.exists()

    def test_compose_config_has_project_name(self, tmp_path: Path) -> None:
        """Config dict includes project.name from root dir."""
        context = self._make_context(tmp_path, ["python"])
        composer = TemplateComposer()
        config = composer.compose_config(context)

        assert config["project"]["name"] == tmp_path.name

    def test_yaml_output_has_header_comment(self, tmp_path: Path) -> None:
        """YAML string starts with header comment."""
        context = self._make_context(tmp_path, ["python"])
        composer = TemplateComposer()
        yaml_str = composer.compose(context)

        assert yaml_str.startswith("# LucidShark Configuration")

    def test_compose_all_14_languages(self, tmp_path: Path) -> None:
        """Composing all 14 languages produces valid merged config."""
        all_languages = list(LANGUAGE_TEMPLATE_MAP.keys())
        context = self._make_context(tmp_path, all_languages)
        composer = TemplateComposer()
        config = composer.compose_config(context)

        # Should have all domains
        pipeline = config["pipeline"]
        assert "linting" in pipeline
        assert "type_checking" in pipeline
        assert "formatting" in pipeline
        assert "security" in pipeline
        assert "testing" in pipeline
        assert "coverage" in pipeline
        assert "duplication" in pipeline

    def test_compose_produces_valid_yaml(self, tmp_path: Path) -> None:
        """Composed YAML string is valid and round-trips correctly."""
        context = self._make_context(tmp_path, ["python", "go", "typescript"])
        composer = TemplateComposer()
        yaml_str = composer.compose(context)

        # Should parse back to dict
        config = yaml.safe_load(yaml_str)
        assert config["version"] == 1
        assert len(config["project"]["languages"]) == 3
