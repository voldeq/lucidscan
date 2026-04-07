"""Validate all template YAML files for correctness."""

from __future__ import annotations


from lucidshark.generation.template_composer import LANGUAGE_TEMPLATE_MAP, load_template


# All known plugin names from the frozen plugin registry in discovery.py
VALID_LINTER_NAMES = {
    "ruff",
    "eslint",
    "biome",
    "clippy",
    "golangci_lint",
    "checkstyle",
    "pmd",
    "ktlint",
    "dotnet_format",
    "clang_tidy",
    "scalafix",
    "swiftlint",
    "rubocop",
    "phpcs",
}

VALID_TYPE_CHECKER_NAMES = {
    "mypy",
    "pyright",
    "typescript",
    "spotbugs",
    "detekt",
    "cargo_check",
    "go_vet",
    "dotnet_build",
    "cppcheck",
    "scala_compile",
    "swift_compiler",
    "sorbet",
    "phpstan",
}

VALID_TEST_RUNNER_NAMES = {
    "pytest",
    "jest",
    "vitest",
    "mocha",
    "karma",
    "playwright",
    "maven",
    "cargo",
    "go_test",
    "dotnet_test",
    "ctest",
    "sbt",
    "swift_test",
    "rspec",
    "phpunit",
}

VALID_COVERAGE_NAMES = {
    "coverage_py",
    "istanbul",
    "vitest_coverage",
    "jacoco",
    "tarpaulin",
    "go_cover",
    "dotnet_coverage",
    "gcov",
    "lcov",
    "scoverage",
    "swift_coverage",
    "simplecov",
    "phpunit_coverage",
}

VALID_FORMATTER_NAMES = {
    "ruff_format",
    "prettier",
    "rustfmt",
    "gofmt",
    "ktlint_format",
    "dotnet_format_whitespace",
    "clang_format",
    "scalafmt",
    "swiftformat",
    "rubocop_format",
    "php_cs_fixer",
}

VALID_SCANNER_NAMES = {"trivy", "opengrep", "gosec", "checkov"}

VALID_DUPLICATION_NAMES = {"duplo"}

VALID_SECURITY_DOMAINS = {"sca", "sast", "iac", "container"}

VALID_PIPELINE_KEYS = {
    "linting",
    "type_checking",
    "formatting",
    "security",
    "testing",
    "coverage",
    "duplication",
}


class TestTemplateFiles:
    """Validate all template YAML files for correctness."""

    def test_every_supported_language_has_template(self) -> None:
        """Every language in LANGUAGE_TEMPLATE_MAP has a loadable template."""
        for language, template_name in LANGUAGE_TEMPLATE_MAP.items():
            template = load_template(language)
            assert template is not None, (
                f"No template found for language '{language}' "
                f"(expected file: {template_name}.yml)"
            )

    def test_all_templates_are_valid_yaml(self) -> None:
        """Load every template and verify it parses as valid YAML with expected structure."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            assert isinstance(template, dict), (
                f"Template for '{language}' did not parse as dict"
            )

    def test_all_templates_have_pipeline_section(self) -> None:
        """Every template must have a pipeline section."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            assert "pipeline" in template, (
                f"Template for '{language}' missing 'pipeline' section"
            )

    def test_all_templates_have_fail_on_section(self) -> None:
        """Every template must have a fail_on section."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            assert "fail_on" in template, (
                f"Template for '{language}' missing 'fail_on' section"
            )

    def test_all_templates_have_ignore_section(self) -> None:
        """Every template must have an ignore section."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            assert "exclude" in template, (
                f"Template for '{language}' missing 'ignore' section"
            )

    def test_all_templates_have_security_domain(self) -> None:
        """Every template must include security scanning."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            pipeline = template["pipeline"]
            assert "security" in pipeline, (
                f"Template for '{language}' missing 'security' in pipeline"
            )
            assert pipeline["security"]["enabled"] is True

    def test_all_templates_have_duplication_domain(self) -> None:
        """Every template must include duplication detection."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            pipeline = template["pipeline"]
            assert "duplication" in pipeline, (
                f"Template for '{language}' missing 'duplication' in pipeline"
            )
            assert pipeline["duplication"]["enabled"] is True

    def test_template_pipeline_keys_are_valid(self) -> None:
        """All pipeline domain names in templates are valid."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            pipeline = template["pipeline"]
            for key in pipeline:
                assert key in VALID_PIPELINE_KEYS, (
                    f"Template for '{language}' has invalid pipeline key: '{key}'"
                )

    def test_template_linter_names_are_valid(self) -> None:
        """All linter tool names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            linting = template["pipeline"].get("linting")
            if linting:
                for tool in linting.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_LINTER_NAMES, (
                        f"Template '{language}': invalid linter '{name}'"
                    )

    def test_template_type_checker_names_are_valid(self) -> None:
        """All type checker tool names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            tc = template["pipeline"].get("type_checking")
            if tc:
                for tool in tc.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_TYPE_CHECKER_NAMES, (
                        f"Template '{language}': invalid type checker '{name}'"
                    )

    def test_template_test_runner_names_are_valid(self) -> None:
        """All test runner tool names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            testing = template["pipeline"].get("testing")
            if testing:
                for tool in testing.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_TEST_RUNNER_NAMES, (
                        f"Template '{language}': invalid test runner '{name}'"
                    )

    def test_template_coverage_names_are_valid(self) -> None:
        """All coverage tool names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            coverage = template["pipeline"].get("coverage")
            if coverage:
                for tool in coverage.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_COVERAGE_NAMES, (
                        f"Template '{language}': invalid coverage tool '{name}'"
                    )

    def test_template_formatter_names_are_valid(self) -> None:
        """All formatter tool names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            formatting = template["pipeline"].get("formatting")
            if formatting:
                for tool in formatting.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_FORMATTER_NAMES, (
                        f"Template '{language}': invalid formatter '{name}'"
                    )

    def test_template_security_tool_names_are_valid(self) -> None:
        """All security scanner names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            security = template["pipeline"].get("security")
            if security:
                for tool in security.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_SCANNER_NAMES, (
                        f"Template '{language}': invalid scanner '{name}'"
                    )

    def test_template_security_domains_are_valid(self) -> None:
        """Security tool domains are valid (sca, sast, iac, container)."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            security = template["pipeline"].get("security")
            if security:
                for tool in security.get("tools", []):
                    if isinstance(tool, dict) and "domains" in tool:
                        for domain in tool["domains"]:
                            assert domain in VALID_SECURITY_DOMAINS, (
                                f"Template '{language}': invalid security domain "
                                f"'{domain}' in tool '{tool['name']}'"
                            )

    def test_template_duplication_tool_names_are_valid(self) -> None:
        """All duplication tool names in templates exist in the registry."""
        for language in LANGUAGE_TEMPLATE_MAP:
            template = load_template(language)
            assert template is not None
            duplication = template["pipeline"].get("duplication")
            if duplication:
                for tool in duplication.get("tools", []):
                    name = tool["name"] if isinstance(tool, dict) else tool
                    assert name in VALID_DUPLICATION_NAMES, (
                        f"Template '{language}': invalid duplication tool '{name}'"
                    )
