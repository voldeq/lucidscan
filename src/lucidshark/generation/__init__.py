"""Configuration generation module.

This module provides generators for:
- lucidshark.yml configuration files (interactive via ConfigGenerator, template-based via TemplateComposer)
- Package manager tool installation
"""

from lucidshark.generation.config_generator import ConfigGenerator, InitChoices
from lucidshark.generation.package_installer import PackageInstaller
from lucidshark.generation.template_composer import TemplateComposer

__all__ = [
    "ConfigGenerator",
    "InitChoices",
    "PackageInstaller",
    "TemplateComposer",
]
