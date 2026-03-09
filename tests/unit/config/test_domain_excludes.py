"""Tests for per-domain exclude pattern configuration.

Tests that exclude patterns can be configured per-domain and are properly
loaded, validated, and combined with global exclude patterns.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from lucidshark.config.ignore import IgnorePatterns
from lucidshark.config.loader import (
    dict_to_config,
    _parse_coverage_pipeline_config,
    _parse_domain_pipeline_config,
)
from lucidshark.config.models import (
    CoveragePipelineConfig,
    DomainPipelineConfig,
    DuplicationPipelineConfig,
    LucidSharkConfig,
)
from lucidshark.config.validation import validate_config
from lucidshark.core.models import ScanContext, ToolDomain


class TestDomainPipelineConfigExclude:
    """Tests for DomainPipelineConfig.exclude field."""

    def test_default_exclude_is_empty(self) -> None:
        """Test that exclude defaults to empty list."""
        config = DomainPipelineConfig()
        assert config.exclude == []

    def test_exclude_stores_patterns(self) -> None:
        """Test that exclude stores provided patterns."""
        config = DomainPipelineConfig(exclude=["scripts/**", "migrations/**"])
        assert config.exclude == ["scripts/**", "migrations/**"]

    def test_exclude_preserves_order(self) -> None:
        """Test that pattern order is preserved."""
        patterns = ["z/**", "a/**", "m/**"]
        config = DomainPipelineConfig(exclude=patterns)
        assert config.exclude == ["z/**", "a/**", "m/**"]

    def test_exclude_allows_empty_list(self) -> None:
        """Test that explicitly passing empty list works."""
        config = DomainPipelineConfig(exclude=[])
        assert config.exclude == []

    def test_exclude_independent_of_enabled(self) -> None:
        """Test that exclude works regardless of enabled state."""
        config = DomainPipelineConfig(enabled=False, exclude=["scripts/**"])
        assert config.exclude == ["scripts/**"]


class TestCoveragePipelineConfigExclude:
    """Tests for CoveragePipelineConfig.exclude field."""

    def test_default_exclude_is_empty(self) -> None:
        """Test that exclude defaults to empty list."""
        config = CoveragePipelineConfig()
        assert config.exclude == []

    def test_exclude_stores_patterns(self) -> None:
        """Test that exclude stores provided patterns."""
        config = CoveragePipelineConfig(exclude=["tests/**", "scripts/**"])
        assert config.exclude == ["tests/**", "scripts/**"]

    def test_exclude_coexists_with_threshold(self) -> None:
        """Test that exclude works alongside threshold configuration."""
        config = CoveragePipelineConfig(
            threshold=90,
            exclude=["tests/**"],
        )
        assert config.threshold == 90
        assert config.exclude == ["tests/**"]

    def test_exclude_coexists_with_extra_args(self) -> None:
        """Test that exclude works alongside extra_args."""
        config = CoveragePipelineConfig(
            extra_args=["-DskipITs"],
            exclude=["integration/**"],
        )
        assert config.extra_args == ["-DskipITs"]
        assert config.exclude == ["integration/**"]


class TestDuplicationPipelineConfigExclude:
    """Tests for DuplicationPipelineConfig.exclude field (pre-existing)."""

    def test_default_exclude_is_empty(self) -> None:
        """Test that exclude defaults to empty list."""
        config = DuplicationPipelineConfig()
        assert config.exclude == []

    def test_exclude_stores_patterns(self) -> None:
        """Test that exclude stores provided patterns."""
        config = DuplicationPipelineConfig(exclude=["generated/**", "vendor/**"])
        assert config.exclude == ["generated/**", "vendor/**"]


class TestConfigLoaderDomainExcludes:
    """Tests for loading domain-specific exclude patterns from config dict."""

    def test_parse_domain_config_with_exclude(self) -> None:
        """Test that _parse_domain_pipeline_config parses exclude field."""
        data: Dict[str, Any] = {
            "enabled": True,
            "tools": [{"name": "ruff"}],
            "exclude": ["scripts/**", "generated/**"],
        }
        result = _parse_domain_pipeline_config(data)
        assert result is not None
        assert result.exclude == ["scripts/**", "generated/**"]

    def test_parse_domain_config_without_exclude(self) -> None:
        """Test that exclude defaults to empty when not specified."""
        data: Dict[str, Any] = {
            "enabled": True,
            "tools": [{"name": "ruff"}],
        }
        result = _parse_domain_pipeline_config(data)
        assert result is not None
        assert result.exclude == []

    def test_parse_domain_config_with_empty_exclude(self) -> None:
        """Test that explicit empty exclude list is preserved."""
        data: Dict[str, Any] = {
            "enabled": True,
            "tools": [{"name": "ruff"}],
            "exclude": [],
        }
        result = _parse_domain_pipeline_config(data)
        assert result is not None
        assert result.exclude == []

    def test_parse_domain_config_none_returns_none(self) -> None:
        """Test that None input returns None."""
        result = _parse_domain_pipeline_config(None)
        assert result is None

    def test_parse_coverage_config_with_exclude(self) -> None:
        """Test that _parse_coverage_pipeline_config parses exclude field."""
        data: Dict[str, Any] = {
            "enabled": True,
            "tools": [{"name": "coverage_py"}],
            "threshold": 80,
            "exclude": ["tests/**"],
        }
        result = _parse_coverage_pipeline_config(data)
        assert result is not None
        assert result.exclude == ["tests/**"]

    def test_parse_coverage_config_without_exclude(self) -> None:
        """Test that exclude defaults to empty when not specified."""
        data: Dict[str, Any] = {
            "enabled": True,
            "tools": [{"name": "coverage_py"}],
        }
        result = _parse_coverage_pipeline_config(data)
        assert result is not None
        assert result.exclude == []

    def test_parse_coverage_config_none_returns_none(self) -> None:
        """Test that None input returns None."""
        result = _parse_coverage_pipeline_config(None)
        assert result is None

    def test_parse_coverage_config_preserves_other_fields(self) -> None:
        """Test that exclude doesn't interfere with threshold and extra_args."""
        data: Dict[str, Any] = {
            "enabled": True,
            "tools": [{"name": "coverage_py"}],
            "threshold": 90,
            "extra_args": ["-DskipITs"],
            "exclude": ["vendor/**"],
        }
        result = _parse_coverage_pipeline_config(data)
        assert result is not None
        assert result.threshold == 90
        assert result.extra_args == ["-DskipITs"]
        assert result.exclude == ["vendor/**"]

    def test_dict_to_config_all_domains_have_exclude(self) -> None:
        """Test that all domain configs parse exclude from full config dict."""
        data: Dict[str, Any] = {
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                    "exclude": ["lint_exclude/**"],
                },
                "type_checking": {
                    "enabled": True,
                    "tools": [{"name": "mypy"}],
                    "exclude": ["tc_exclude/**"],
                },
                "security": {
                    "enabled": True,
                    "tools": [{"name": "trivy", "domains": ["sca"]}],
                    "exclude": ["sec_exclude/**"],
                },
                "testing": {
                    "enabled": True,
                    "tools": [{"name": "pytest"}],
                    "exclude": ["test_exclude/**"],
                },
                "coverage": {
                    "enabled": True,
                    "tools": [{"name": "coverage_py"}],
                    "exclude": ["cov_exclude/**"],
                },
                "duplication": {
                    "enabled": True,
                    "tools": [{"name": "duplo"}],
                    "exclude": ["dup_exclude/**"],
                },
            }
        }
        config = dict_to_config(data)
        assert config.pipeline.linting is not None
        assert config.pipeline.linting.exclude == ["lint_exclude/**"]
        assert config.pipeline.type_checking is not None
        assert config.pipeline.type_checking.exclude == ["tc_exclude/**"]
        assert config.pipeline.security is not None
        assert config.pipeline.security.exclude == ["sec_exclude/**"]
        assert config.pipeline.testing is not None
        assert config.pipeline.testing.exclude == ["test_exclude/**"]
        assert config.pipeline.coverage is not None
        assert config.pipeline.coverage.exclude == ["cov_exclude/**"]
        assert config.pipeline.duplication is not None
        assert config.pipeline.duplication.exclude == ["dup_exclude/**"]

    def test_dict_to_config_domains_without_exclude(self) -> None:
        """Test that domains without exclude get empty lists."""
        data: Dict[str, Any] = {
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                },
                "type_checking": {
                    "enabled": True,
                    "tools": [{"name": "mypy"}],
                },
            }
        }
        config = dict_to_config(data)
        assert config.pipeline.linting is not None
        assert config.pipeline.linting.exclude == []
        assert config.pipeline.type_checking is not None
        assert config.pipeline.type_checking.exclude == []

    def test_dict_to_config_unconfigured_domains_are_none(self) -> None:
        """Test that domains not in the config dict remain None."""
        data: Dict[str, Any] = {}
        config = dict_to_config(data)
        assert config.pipeline.linting is None
        assert config.pipeline.type_checking is None
        assert config.pipeline.security is None
        assert config.pipeline.testing is None
        assert config.pipeline.coverage is None
        assert config.pipeline.duplication is None


class TestTopLevelExcludeKey:
    """Tests for the top-level 'exclude' key (alias for 'ignore')."""

    def test_exclude_key_maps_to_ignore(self) -> None:
        """Test that top-level 'exclude' key populates config.ignore."""
        data: Dict[str, Any] = {
            "exclude": ["**/.venv/**", "**/dist/**"],
        }
        config = dict_to_config(data)
        assert config.ignore == ["**/.venv/**", "**/dist/**"]

    def test_ignore_key_still_works(self) -> None:
        """Test backward compatibility: 'ignore' key still works."""
        data: Dict[str, Any] = {
            "ignore": ["**/.venv/**"],
        }
        config = dict_to_config(data)
        assert config.ignore == ["**/.venv/**"]

    def test_exclude_takes_precedence_over_ignore(self) -> None:
        """Test that 'exclude' takes precedence when both are specified."""
        data: Dict[str, Any] = {
            "ignore": ["old_pattern/**"],
            "exclude": ["new_pattern/**"],
        }
        config = dict_to_config(data)
        # dict_to_config uses: data.get("exclude", data.get("ignore", []))
        # When "exclude" is present, it wins.
        assert config.ignore == ["new_pattern/**"]

    def test_neither_key_defaults_to_empty(self) -> None:
        """Test that config.ignore is empty when neither key is present."""
        data: Dict[str, Any] = {}
        config = dict_to_config(data)
        assert config.ignore == []

    def test_exclude_key_with_empty_list(self) -> None:
        """Test that empty exclude list is preserved."""
        data: Dict[str, Any] = {"exclude": []}
        config = dict_to_config(data)
        assert config.ignore == []

    def test_ignore_fallback_when_exclude_absent(self) -> None:
        """Test that ignore is used as fallback when exclude is absent."""
        data: Dict[str, Any] = {
            "ignore": ["fallback_pattern/**"],
        }
        config = dict_to_config(data)
        assert config.ignore == ["fallback_pattern/**"]


class TestConfigValidationExcludes:
    """Tests for validation of exclude patterns in config."""

    def test_top_level_exclude_is_valid(self) -> None:
        """Test that 'exclude' is recognized as valid top-level key."""
        data: Dict[str, Any] = {"exclude": ["**/.venv/**"]}
        warnings = validate_config(data, "test.yml")
        # Should not have "Unknown top-level key 'exclude'" warning
        assert not any(
            "exclude" in w.message and "Unknown" in w.message for w in warnings
        )

    def test_top_level_exclude_must_be_list(self) -> None:
        """Test that non-list 'exclude' produces warning."""
        data: Dict[str, Any] = {"exclude": "not-a-list"}
        warnings = validate_config(data, "test.yml")
        assert any("'exclude' must be a list" in w.message for w in warnings)

    def test_top_level_exclude_valid_list(self) -> None:
        """Test that valid list exclude produces no warnings."""
        data: Dict[str, Any] = {"exclude": ["**/.venv/**", "**/dist/**"]}
        warnings = validate_config(data, "test.yml")
        exclude_warnings = [w for w in warnings if "exclude" in (w.key or "")]
        assert len(exclude_warnings) == 0

    def test_domain_exclude_is_valid_key_linting(self) -> None:
        """Test that 'exclude' is valid in pipeline.linting section."""
        data: Dict[str, Any] = {
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                    "exclude": ["pattern/**"],
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        unknown_key_warnings = [
            w
            for w in warnings
            if "pipeline.linting.exclude" in (w.key or "") and "Unknown" in w.message
        ]
        assert not unknown_key_warnings

    def test_domain_exclude_is_valid_key_type_checking(self) -> None:
        """Test that 'exclude' is valid in pipeline.type_checking section."""
        data: Dict[str, Any] = {
            "pipeline": {
                "type_checking": {
                    "enabled": True,
                    "tools": [{"name": "mypy"}],
                    "exclude": ["stubs/**"],
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        unknown_key_warnings = [
            w
            for w in warnings
            if "pipeline.type_checking.exclude" in (w.key or "")
            and "Unknown" in w.message
        ]
        assert not unknown_key_warnings

    def test_domain_exclude_is_valid_key_testing(self) -> None:
        """Test that 'exclude' is valid in pipeline.testing section."""
        data: Dict[str, Any] = {
            "pipeline": {
                "testing": {
                    "enabled": True,
                    "tools": [{"name": "pytest"}],
                    "exclude": ["integration/**"],
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        unknown_key_warnings = [
            w
            for w in warnings
            if "pipeline.testing.exclude" in (w.key or "") and "Unknown" in w.message
        ]
        assert not unknown_key_warnings

    def test_coverage_exclude_is_valid_key(self) -> None:
        """Test that 'exclude' is valid in coverage section."""
        data: Dict[str, Any] = {
            "pipeline": {
                "coverage": {
                    "enabled": True,
                    "tools": [{"name": "coverage_py"}],
                    "exclude": ["tests/**"],
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        unknown_key_warnings = [
            w
            for w in warnings
            if "pipeline.coverage.exclude" in (w.key or "") and "Unknown" in w.message
        ]
        assert not unknown_key_warnings

    def test_security_exclude_is_valid_key(self) -> None:
        """Test that 'exclude' is valid in security section."""
        data: Dict[str, Any] = {
            "pipeline": {
                "security": {
                    "enabled": True,
                    "tools": [{"name": "trivy", "domains": ["sca"]}],
                    "exclude": ["tests/**"],
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        unknown_key_warnings = [
            w
            for w in warnings
            if "pipeline.security.exclude" in (w.key or "") and "Unknown" in w.message
        ]
        assert not unknown_key_warnings

    def test_duplication_exclude_is_valid_key(self) -> None:
        """Test that 'exclude' is valid in duplication section."""
        data: Dict[str, Any] = {
            "pipeline": {
                "duplication": {
                    "enabled": True,
                    "tools": [{"name": "duplo"}],
                    "exclude": ["generated/**"],
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        unknown_key_warnings = [
            w
            for w in warnings
            if "pipeline.duplication.exclude" in (w.key or "")
            and "Unknown" in w.message
        ]
        assert not unknown_key_warnings

    def test_domain_exclude_must_be_list_linting(self) -> None:
        """Test that non-list linting exclude produces warning."""
        data: Dict[str, Any] = {
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                    "exclude": "not-a-list",
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        assert any(
            "pipeline.linting.exclude" in (w.key or "")
            and "must be a list" in w.message
            for w in warnings
        )

    def test_domain_exclude_must_be_list_type_checking(self) -> None:
        """Test that non-list type_checking exclude produces warning."""
        data: Dict[str, Any] = {
            "pipeline": {
                "type_checking": {
                    "enabled": True,
                    "tools": [{"name": "mypy"}],
                    "exclude": "not-a-list",
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        assert any(
            "pipeline.type_checking.exclude" in (w.key or "")
            and "must be a list" in w.message
            for w in warnings
        )

    def test_domain_exclude_must_be_list_coverage(self) -> None:
        """Test that non-list coverage exclude produces warning."""
        data: Dict[str, Any] = {
            "pipeline": {
                "coverage": {
                    "enabled": True,
                    "tools": [{"name": "coverage_py"}],
                    "exclude": "not-a-list",
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        assert any(
            "pipeline.coverage.exclude" in (w.key or "")
            and "must be a list" in w.message
            for w in warnings
        )

    def test_domain_exclude_must_be_list_security(self) -> None:
        """Test that non-list security exclude produces warning."""
        data: Dict[str, Any] = {
            "pipeline": {
                "security": {
                    "enabled": True,
                    "tools": [{"name": "trivy", "domains": ["sca"]}],
                    "exclude": "not-a-list",
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        assert any(
            "pipeline.security.exclude" in (w.key or "")
            and "must be a list" in w.message
            for w in warnings
        )

    def test_domain_exclude_must_be_list_duplication(self) -> None:
        """Test that non-list duplication exclude produces warning."""
        data: Dict[str, Any] = {
            "pipeline": {
                "duplication": {
                    "enabled": True,
                    "tools": [{"name": "duplo"}],
                    "exclude": "not-a-list",
                }
            }
        }
        warnings = validate_config(data, "test.yml")
        assert any(
            "pipeline.duplication.exclude" in (w.key or "")
            and "must be a list" in w.message
            for w in warnings
        )

    def test_all_domains_exclude_valid_produces_no_warnings(self) -> None:
        """Test that valid excludes in all domains produce no exclude-related warnings."""
        data: Dict[str, Any] = {
            "exclude": ["global/**"],
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                    "exclude": ["lint/**"],
                },
                "type_checking": {
                    "enabled": True,
                    "tools": [{"name": "mypy"}],
                    "exclude": ["tc/**"],
                },
                "testing": {
                    "enabled": True,
                    "tools": [{"name": "pytest"}],
                    "exclude": ["test/**"],
                },
                "coverage": {
                    "enabled": True,
                    "tools": [{"name": "coverage_py"}],
                    "exclude": ["cov/**"],
                },
                "security": {
                    "enabled": True,
                    "tools": [{"name": "trivy", "domains": ["sca"]}],
                    "exclude": ["sec/**"],
                },
                "duplication": {
                    "enabled": True,
                    "tools": [{"name": "duplo"}],
                    "exclude": ["dup/**"],
                },
            },
        }
        warnings = validate_config(data, "test.yml")
        exclude_warnings = [
            w for w in warnings if "exclude" in (w.key or "") and "Unknown" in w.message
        ]
        assert not exclude_warnings


class TestDomainRunnerExcludePatterns:
    """Tests for DomainRunner domain-specific exclude pattern handling."""

    def test_context_with_domain_excludes_merges_patterns(self) -> None:
        """Test that _context_with_domain_excludes merges domain patterns with global."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig(ignore=["**/.venv/**"])
        runner = DomainRunner(Path("/project"), config)

        global_ignore = IgnorePatterns(["**/.venv/**"], source="global")
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=global_ignore,
        )

        new_context = runner._context_with_domain_excludes(
            context, ["scripts/**", "migrations/**"]
        )

        patterns = new_context.get_exclude_patterns()
        # Should contain both global and domain-specific patterns
        assert "**/.venv/**" in patterns
        assert "scripts/**" in patterns
        assert "migrations/**" in patterns

    def test_context_with_domain_excludes_returns_same_when_none(self) -> None:
        """Test that None exclude_patterns returns the same context."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
        )

        result = runner._context_with_domain_excludes(context, None)
        assert result is context  # Should be the exact same object

    def test_context_with_domain_excludes_returns_same_when_empty(self) -> None:
        """Test that empty exclude_patterns returns the same context."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
        )

        result = runner._context_with_domain_excludes(context, [])
        assert result is context

    def test_context_with_domain_excludes_preserves_other_fields(self) -> None:
        """Test that only ignore_patterns changes, other fields are preserved."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        original_paths = [Path("/project/src")]
        context = ScanContext(
            project_root=Path("/project"),
            paths=original_paths,
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=IgnorePatterns(["global/**"]),
        )

        new_context = runner._context_with_domain_excludes(context, ["domain/**"])

        assert new_context.project_root == context.project_root
        assert new_context.paths == context.paths
        assert new_context.enabled_domains == context.enabled_domains

    def test_context_with_domain_excludes_handles_no_global_patterns(self) -> None:
        """Test domain excludes work when there are no global patterns."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=None,
        )

        new_context = runner._context_with_domain_excludes(context, ["domain/**"])
        patterns = new_context.get_exclude_patterns()
        assert "domain/**" in patterns

    def test_context_with_domain_excludes_does_not_mutate_original(self) -> None:
        """Test that the original context's ignore_patterns is not mutated."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        global_ignore = IgnorePatterns(["global/**"], source="global")
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=global_ignore,
        )

        original_patterns = context.get_exclude_patterns()
        runner._context_with_domain_excludes(context, ["domain/**"])

        # Original context should be unchanged
        assert context.get_exclude_patterns() == original_patterns

    def test_context_with_domain_excludes_new_context_is_different(self) -> None:
        """Test that a new ScanContext object is returned (not the same reference)."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=IgnorePatterns(["global/**"]),
        )

        new_context = runner._context_with_domain_excludes(context, ["domain/**"])
        assert new_context is not context

    def test_context_with_multiple_domain_patterns(self) -> None:
        """Test merging with multiple domain-specific patterns."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=IgnorePatterns(["global/**"]),
        )

        domain_patterns = [
            "scripts/**",
            "migrations/**",
            "generated/**",
            "vendor/**",
        ]
        new_context = runner._context_with_domain_excludes(context, domain_patterns)
        patterns = new_context.get_exclude_patterns()

        assert "global/**" in patterns
        for dp in domain_patterns:
            assert dp in patterns


class TestCombiningGlobalAndDomainExcludes:
    """Tests for the full flow of combining global + domain excludes."""

    def test_full_config_with_global_and_domain_excludes(self) -> None:
        """Test loading a config with both global and per-domain excludes."""
        data: Dict[str, Any] = {
            "exclude": ["**/node_modules/**"],
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                    "exclude": ["scripts/**"],
                },
                "type_checking": {
                    "enabled": True,
                    "tools": [{"name": "mypy"}],
                    "exclude": ["tests/conftest.py"],
                },
            },
        }
        config = dict_to_config(data)

        # Global excludes go to config.ignore
        assert config.ignore == ["**/node_modules/**"]

        # Domain excludes are on their respective configs
        assert config.pipeline.linting is not None
        assert config.pipeline.linting.exclude == ["scripts/**"]
        assert config.pipeline.type_checking is not None
        assert config.pipeline.type_checking.exclude == ["tests/conftest.py"]

    def test_domain_excludes_do_not_affect_other_domains(self) -> None:
        """Test that domain-specific excludes don't leak to other domains."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        global_ignore = IgnorePatterns(["**/.venv/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=global_ignore,
        )

        # Create linting context with linting-specific excludes
        linting_ctx = runner._context_with_domain_excludes(context, ["scripts/**"])

        # Original context should be unchanged
        original_patterns = context.get_exclude_patterns()
        assert "scripts/**" not in original_patterns

        # Linting context should have both
        linting_patterns = linting_ctx.get_exclude_patterns()
        assert "**/.venv/**" in linting_patterns
        assert "scripts/**" in linting_patterns

    def test_two_domains_get_different_excludes(self) -> None:
        """Test that two different domains can have independent excludes."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        global_ignore = IgnorePatterns(["**/.venv/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING, ToolDomain.TYPE_CHECKING],
            ignore_patterns=global_ignore,
        )

        linting_ctx = runner._context_with_domain_excludes(context, ["lint_only/**"])
        tc_ctx = runner._context_with_domain_excludes(context, ["tc_only/**"])

        linting_patterns = linting_ctx.get_exclude_patterns()
        tc_patterns = tc_ctx.get_exclude_patterns()

        # Both should have global pattern
        assert "**/.venv/**" in linting_patterns
        assert "**/.venv/**" in tc_patterns

        # Each should have its own domain pattern
        assert "lint_only/**" in linting_patterns
        assert "lint_only/**" not in tc_patterns

        assert "tc_only/**" in tc_patterns
        assert "tc_only/**" not in linting_patterns

    def test_global_and_domain_excludes_combined_in_runner(self) -> None:
        """Test end-to-end flow: config loaded, then runner merges patterns."""
        data: Dict[str, Any] = {
            "exclude": ["**/node_modules/**", "**/.git/**"],
            "pipeline": {
                "linting": {
                    "enabled": True,
                    "tools": [{"name": "ruff"}],
                    "exclude": ["scripts/**", "generated/**"],
                },
            },
        }
        config = dict_to_config(data)

        from lucidshark.core.domain_runner import DomainRunner

        runner = DomainRunner(Path("/project"), config)

        global_ignore = IgnorePatterns(config.ignore, source="config")
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=global_ignore,
        )

        linting_exclude = (
            config.pipeline.linting.exclude if config.pipeline.linting else []
        )
        linting_ctx = runner._context_with_domain_excludes(context, linting_exclude)

        patterns = linting_ctx.get_exclude_patterns()
        assert "**/node_modules/**" in patterns
        assert "**/.git/**" in patterns
        assert "scripts/**" in patterns
        assert "generated/**" in patterns

    def test_domain_with_no_excludes_gets_only_global(self) -> None:
        """Test that a domain without excludes only has global patterns."""
        from lucidshark.core.domain_runner import DomainRunner

        config = LucidSharkConfig()
        runner = DomainRunner(Path("/project"), config)

        global_ignore = IgnorePatterns(["**/.venv/**", "**/dist/**"])
        context = ScanContext(
            project_root=Path("/project"),
            paths=[],
            enabled_domains=[ToolDomain.LINTING],
            ignore_patterns=global_ignore,
        )

        # Pass empty list -- should return same context
        result = runner._context_with_domain_excludes(context, [])
        assert result is context
        patterns = result.get_exclude_patterns()
        assert "**/.venv/**" in patterns
        assert "**/dist/**" in patterns
