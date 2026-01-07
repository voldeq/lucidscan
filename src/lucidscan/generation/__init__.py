"""Configuration and CI generation module.

This module provides generators for:
- lucidscan.yml configuration files
- CI/CD pipeline configurations (GitHub Actions, GitLab CI, Bitbucket)
- Package manager tool installation
"""

from lucidscan.generation.config_generator import ConfigGenerator, InitChoices
from lucidscan.generation.ci_generator import CIGenerator
from lucidscan.generation.package_installer import PackageInstaller

__all__ = [
    "ConfigGenerator",
    "CIGenerator",
    "InitChoices",
    "PackageInstaller",
]
