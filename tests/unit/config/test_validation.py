"""Tests for lucidscan.config.validation."""

from __future__ import annotations

from pathlib import Path

from lucidscan.config.validation import (
    ConfigValidationWarning,
    ConfigValidationIssue,
    ValidationSeverity,
    validate_config,
    validate_config_file,
    _suggest_key,
)


class TestSuggestKey:
    """Tests for _suggest_key function."""

    def test_suggests_close_match(self) -> None:
        result = _suggest_key("sac", {"sca", "sast", "iac"})
        assert result == "sca"

    def test_suggests_typo_fix(self) -> None:
        result = _suggest_key("faol_on", {"fail_on", "ignore", "output"})
        assert result == "fail_on"

    def test_returns_none_for_no_match(self) -> None:
        result = _suggest_key("xyz", {"fail_on", "ignore", "output"})
        assert result is None

    def test_handles_empty_valid_keys(self) -> None:
        result = _suggest_key("test", set())
        assert result is None


class TestValidateConfig:
    """Tests for validate_config function."""

    def test_valid_config_returns_no_warnings(self) -> None:
        data = {
            "fail_on": "high",
            "ignore": ["tests/**"],
            "output": {"format": "json"},
            "scanners": {
                "sca": {"enabled": True},
            },
        }
        warnings = validate_config(data, source="test.yml")
        # Filter out INFO-level warnings
        errors = [w for w in warnings if "Unknown" in w.message]
        assert len(errors) == 0

    def test_warns_on_unknown_top_level_key(self) -> None:
        data = {"unknown_key": "value"}
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "unknown_key" in warnings[0].message
        assert warnings[0].key == "unknown_key"

    def test_suggests_typo_fix_for_top_level(self) -> None:
        data = {"fail_ob": "high"}  # typo: should be fail_on
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert warnings[0].suggestion == "fail_on"

    def test_warns_on_invalid_fail_on_severity(self) -> None:
        data = {"fail_on": "super_high"}  # invalid severity
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "Invalid severity" in warnings[0].message

    def test_warns_on_invalid_fail_on_type(self) -> None:
        data = {"fail_on": 123}  # should be string
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "must be a string" in warnings[0].message

    def test_warns_on_invalid_ignore_type(self) -> None:
        data = {"ignore": "should-be-list"}  # should be list
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "must be a list" in warnings[0].message

    def test_warns_on_invalid_output_type(self) -> None:
        data = {"output": "json"}  # should be dict
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "must be a mapping" in warnings[0].message

    def test_warns_on_unknown_output_key(self) -> None:
        data = {"output": {"unknown": "value"}}
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "output.unknown" in warnings[0].message

    def test_warns_on_invalid_scanners_type(self) -> None:
        data = {"scanners": ["sca"]}  # should be dict
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "must be a mapping" in warnings[0].message

    def test_warns_on_unknown_domain(self) -> None:
        data = {"scanners": {"unknowndomain": {"enabled": True}}}
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "Unknown scanner domain" in warnings[0].message

    def test_suggests_domain_typo_fix(self) -> None:
        data = {"scanners": {"sac": {"enabled": True}}}  # typo: should be sca
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert warnings[0].suggestion == "sca"

    def test_warns_on_invalid_enabled_type(self) -> None:
        data = {"scanners": {"sca": {"enabled": "yes"}}}  # should be bool
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "must be a boolean" in warnings[0].message

    def test_warns_on_invalid_plugin_type(self) -> None:
        data = {"scanners": {"sca": {"plugin": 123}}}  # should be string
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 1
        assert "must be a string" in warnings[0].message

    def test_allows_plugin_specific_options(self) -> None:
        # Plugin-specific options should not trigger warnings
        data = {
            "scanners": {
                "sca": {
                    "enabled": True,
                    "plugin": "trivy",
                    "ignore_unfixed": True,  # plugin-specific
                    "severity": ["HIGH"],  # plugin-specific
                    "custom_option": "value",  # plugin-specific
                },
            }
        }
        warnings = validate_config(data, source="test.yml")
        assert len(warnings) == 0

    def test_returns_warning_for_non_dict_data(self) -> None:
        warnings = validate_config("not a dict", source="test.yml")  # type: ignore[arg-type]
        assert len(warnings) == 1
        assert "must be a mapping" in warnings[0].message


class TestConfigValidationWarning:
    """Tests for ConfigValidationWarning dataclass."""

    def test_basic_warning(self) -> None:
        warning = ConfigValidationWarning(
            message="Test message",
            source="test.yml",
        )
        assert warning.message == "Test message"
        assert warning.source == "test.yml"
        assert warning.key is None
        assert warning.suggestion is None

    def test_warning_with_key_and_suggestion(self) -> None:
        warning = ConfigValidationWarning(
            message="Unknown key",
            source="test.yml",
            key="fail_ob",
            suggestion="fail_on",
        )
        assert warning.key == "fail_ob"
        assert warning.suggestion == "fail_on"


class TestValidateConfigFile:
    """Tests for validate_config_file function."""

    def test_valid_config_returns_valid(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_on: high\nignore:\n  - tests/**\n")

        is_valid, issues = validate_config_file(config_file)

        assert is_valid is True
        assert len(issues) == 0

    def test_nonexistent_file_returns_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "nonexistent.yml"

        is_valid, issues = validate_config_file(config_file)

        assert is_valid is False
        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.ERROR
        assert "not found" in issues[0].message

    def test_yaml_syntax_error_returns_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("invalid: yaml: content:\n  - bad")

        is_valid, issues = validate_config_file(config_file)

        assert is_valid is False
        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.ERROR
        assert "YAML" in issues[0].message

    def test_empty_file_returns_warning(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("")

        is_valid, issues = validate_config_file(config_file)

        # Empty file is valid but has a warning
        assert is_valid is True
        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.WARNING
        assert "empty" in issues[0].message

    def test_unknown_key_returns_warning(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("unknown_key: value\n")

        is_valid, issues = validate_config_file(config_file)

        # Unknown keys are warnings, not errors
        assert is_valid is True
        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.WARNING
        assert "unknown_key" in issues[0].message

    def test_type_error_returns_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_on: 123\n")  # Should be string

        is_valid, issues = validate_config_file(config_file)

        assert is_valid is False
        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.ERROR
        assert "must be a" in issues[0].message

    def test_invalid_severity_returns_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_on: super_high\n")  # Invalid severity

        is_valid, issues = validate_config_file(config_file)

        assert is_valid is False
        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.ERROR
        assert "Invalid severity" in issues[0].message

    def test_typo_suggestion_included(self, tmp_path: Path) -> None:
        config_file = tmp_path / "lucidscan.yml"
        config_file.write_text("fail_ob: high\n")  # Typo: should be fail_on

        is_valid, issues = validate_config_file(config_file)

        assert is_valid is True  # Unknown key is just a warning
        assert len(issues) == 1
        assert issues[0].suggestion == "fail_on"


class TestValidationSeverity:
    """Tests for ValidationSeverity enum."""

    def test_error_value(self) -> None:
        assert ValidationSeverity.ERROR.value == "error"

    def test_warning_value(self) -> None:
        assert ValidationSeverity.WARNING.value == "warning"


class TestConfigValidationIssue:
    """Tests for ConfigValidationIssue dataclass."""

    def test_basic_issue(self) -> None:
        issue = ConfigValidationIssue(
            message="Test message",
            source="test.yml",
            severity=ValidationSeverity.ERROR,
        )
        assert issue.message == "Test message"
        assert issue.source == "test.yml"
        assert issue.severity == ValidationSeverity.ERROR
        assert issue.key is None
        assert issue.suggestion is None

    def test_issue_with_all_fields(self) -> None:
        issue = ConfigValidationIssue(
            message="Unknown key",
            source="test.yml",
            severity=ValidationSeverity.WARNING,
            key="fail_ob",
            suggestion="fail_on",
        )
        assert issue.key == "fail_ob"
        assert issue.suggestion == "fail_on"
        assert issue.severity == ValidationSeverity.WARNING
