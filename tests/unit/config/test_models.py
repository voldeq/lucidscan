"""Tests for lucidshark.config.models."""

from __future__ import annotations


from lucidshark.config.models import (
    CoveragePipelineConfig,
    DEFAULT_PLUGINS,
    DomainPipelineConfig,
    IgnoreIssueEntry,
    LucidSharkConfig,
    OutputConfig,
    ScannerDomainConfig,
)


class TestOutputConfig:
    """Tests for OutputConfig dataclass."""

    def test_default_format_is_json(self) -> None:
        config = OutputConfig()
        assert config.format == "json"

    def test_custom_format(self) -> None:
        config = OutputConfig(format="table")
        assert config.format == "table"


class TestScannerDomainConfig:
    """Tests for ScannerDomainConfig dataclass."""

    def test_default_enabled_is_true(self) -> None:
        config = ScannerDomainConfig()
        assert config.enabled is True

    def test_default_plugin_is_empty(self) -> None:
        config = ScannerDomainConfig()
        assert config.plugin == ""

    def test_default_options_is_empty_dict(self) -> None:
        config = ScannerDomainConfig()
        assert config.options == {}

    def test_custom_values(self) -> None:
        config = ScannerDomainConfig(
            enabled=False,
            plugin="snyk",
            options={"api_token": "test"},
        )
        assert config.enabled is False
        assert config.plugin == "snyk"
        assert config.options == {"api_token": "test"}


class TestDefaultPlugins:
    """Tests for DEFAULT_PLUGINS mapping."""

    def test_sca_defaults_to_trivy(self) -> None:
        assert DEFAULT_PLUGINS["sca"] == "trivy"

    def test_container_defaults_to_trivy(self) -> None:
        assert DEFAULT_PLUGINS["container"] == "trivy"

    def test_sast_defaults_to_opengrep(self) -> None:
        assert DEFAULT_PLUGINS["sast"] == "opengrep"

    def test_iac_defaults_to_checkov(self) -> None:
        assert DEFAULT_PLUGINS["iac"] == "checkov"


class TestLucidSharkConfig:
    """Tests for LucidSharkConfig dataclass."""

    def test_default_fail_on_is_none(self) -> None:
        config = LucidSharkConfig()
        assert config.fail_on is None

    def test_default_ignore_is_empty_list(self) -> None:
        config = LucidSharkConfig()
        assert config.ignore == []

    def test_default_output_is_json(self) -> None:
        config = LucidSharkConfig()
        assert config.output.format == "json"

    def test_default_scanners_is_empty_dict(self) -> None:
        config = LucidSharkConfig()
        assert config.scanners == {}

    def test_default_enrichers_is_empty_dict(self) -> None:
        config = LucidSharkConfig()
        assert config.enrichers == {}

    def test_custom_values(self) -> None:
        config = LucidSharkConfig(
            fail_on="high",
            ignore=["tests/**"],
            output=OutputConfig(format="table"),
        )
        assert config.fail_on == "high"
        assert config.ignore == ["tests/**"]
        assert config.output.format == "table"


class TestLucidSharkConfigGetScannerConfig:
    """Tests for LucidSharkConfig.get_scanner_config method."""

    def test_returns_default_for_unconfigured_domain(self) -> None:
        config = LucidSharkConfig()
        domain_config = config.get_scanner_config("sca")
        assert domain_config.enabled is True
        assert domain_config.plugin == ""
        assert domain_config.options == {}

    def test_returns_configured_domain(self) -> None:
        config = LucidSharkConfig(
            scanners={
                "sca": ScannerDomainConfig(
                    enabled=False,
                    plugin="snyk",
                    options={"api_token": "test"},
                ),
            }
        )
        domain_config = config.get_scanner_config("sca")
        assert domain_config.enabled is False
        assert domain_config.plugin == "snyk"
        assert domain_config.options == {"api_token": "test"}


class TestLucidSharkConfigGetEnabledDomains:
    """Tests for LucidSharkConfig.get_enabled_domains method."""

    def test_returns_empty_list_when_no_scanners(self) -> None:
        config = LucidSharkConfig()
        assert config.get_enabled_domains() == []

    def test_returns_enabled_domains(self) -> None:
        config = LucidSharkConfig(
            scanners={
                "sca": ScannerDomainConfig(enabled=True),
                "sast": ScannerDomainConfig(enabled=False),
                "iac": ScannerDomainConfig(enabled=True),
            }
        )
        enabled = config.get_enabled_domains()
        assert "sca" in enabled
        assert "sast" not in enabled
        assert "iac" in enabled


class TestLucidSharkConfigGetPluginForDomain:
    """Tests for LucidSharkConfig.get_plugin_for_domain method."""

    def test_returns_default_plugin_when_not_configured(self) -> None:
        config = LucidSharkConfig()
        assert config.get_plugin_for_domain("sca") == "trivy"
        assert config.get_plugin_for_domain("sast") == "opengrep"
        assert config.get_plugin_for_domain("iac") == "checkov"
        assert config.get_plugin_for_domain("container") == "trivy"

    def test_returns_configured_plugin(self) -> None:
        config = LucidSharkConfig(
            scanners={
                "sca": ScannerDomainConfig(plugin="snyk"),
            }
        )
        assert config.get_plugin_for_domain("sca") == "snyk"

    def test_returns_empty_string_for_unknown_domain(self) -> None:
        config = LucidSharkConfig()
        assert config.get_plugin_for_domain("unknown") == ""


class TestDomainPipelineConfigExclude:
    """Tests for DomainPipelineConfig exclude field."""

    def test_default_exclude_is_empty_list(self) -> None:
        config = DomainPipelineConfig()
        assert config.exclude == []

    def test_custom_exclude_patterns(self) -> None:
        config = DomainPipelineConfig(exclude=["tests/**", "*.generated.py"])
        assert config.exclude == ["tests/**", "*.generated.py"]


class TestCoveragePipelineConfigExclude:
    """Tests for CoveragePipelineConfig exclude field."""

    def test_default_exclude_is_empty_list(self) -> None:
        config = CoveragePipelineConfig()
        assert config.exclude == []

    def test_custom_exclude_patterns(self) -> None:
        config = CoveragePipelineConfig(exclude=["vendor/**"])
        assert config.exclude == ["vendor/**"]


class TestLucidSharkConfigGetScannerOptions:
    """Tests for LucidSharkConfig.get_scanner_options method."""

    def test_returns_empty_dict_when_no_options(self) -> None:
        config = LucidSharkConfig()
        assert config.get_scanner_options("sca") == {}

    def test_returns_configured_options(self) -> None:
        config = LucidSharkConfig(
            scanners={
                "sca": ScannerDomainConfig(
                    options={"ignore_unfixed": True, "severity": ["HIGH"]},
                ),
            }
        )
        options = config.get_scanner_options("sca")
        assert options["ignore_unfixed"] is True
        assert options["severity"] == ["HIGH"]


class TestIgnoreIssueEntry:
    """Tests for IgnoreIssueEntry dataclass."""

    def test_simple_rule_id(self) -> None:
        entry = IgnoreIssueEntry(rule_id="E501")
        assert entry.rule_id == "E501"
        assert entry.reason is None
        assert entry.expires is None

    def test_with_reason_and_expires(self) -> None:
        entry = IgnoreIssueEntry(
            rule_id="CVE-2021-1234",
            reason="Accepted risk",
            expires="2026-12-31",
        )
        assert entry.rule_id == "CVE-2021-1234"
        assert entry.reason == "Accepted risk"
        assert entry.expires == "2026-12-31"


class TestLucidSharkConfigIgnoreIssues:
    """Tests for ignore_issues field on LucidSharkConfig."""

    def test_default_ignore_issues_is_empty(self) -> None:
        config = LucidSharkConfig()
        assert config.ignore_issues == []

    def test_custom_ignore_issues(self) -> None:
        config = LucidSharkConfig(
            ignore_issues=[
                IgnoreIssueEntry(rule_id="E501"),
                IgnoreIssueEntry(rule_id="CVE-2021-1234", reason="accepted"),
            ]
        )
        assert len(config.ignore_issues) == 2
        assert config.ignore_issues[0].rule_id == "E501"
        assert config.ignore_issues[1].reason == "accepted"
