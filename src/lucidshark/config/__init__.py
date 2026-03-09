"""Configuration module for lucidshark.

Provides configuration file loading, parsing, and validation with support for:
- Project-level config (.lucidshark.yml)
- Global config (~/.lucidshark/config/config.yml)
- Environment variable expansion
- Plugin-specific configuration passthrough
"""

from lucidshark.config.models import (
    LucidSharkConfig,
    OutputConfig,
    ScannerDomainConfig,
    DEFAULT_PLUGINS,
)
from lucidshark.config.loader import (
    load_config,
    find_project_config,
    find_global_config,
)
from lucidshark.config.validation import validate_config, ConfigValidationWarning

__all__ = [
    "LucidSharkConfig",
    "OutputConfig",
    "ScannerDomainConfig",
    "DEFAULT_PLUGINS",
    "load_config",
    "find_project_config",
    "find_global_config",
    "validate_config",
    "ConfigValidationWarning",
]
