"""Bridge between CLI arguments and configuration models."""

from __future__ import annotations

import argparse
from typing import Any, Dict, List

from lucidscan.config.models import LucidScanConfig
from lucidscan.core.logging import get_logger
from lucidscan.core.models import ScanDomain

LOGGER = get_logger(__name__)


class ConfigBridge:
    """Translates CLI arguments to configuration objects."""

    @staticmethod
    def args_to_overrides(args: argparse.Namespace) -> Dict[str, Any]:
        """Convert CLI arguments to config override dict.

        CLI arguments take precedence over config file values.

        Args:
            args: Parsed CLI arguments.

        Returns:
            Dictionary of config overrides.
        """
        overrides: Dict[str, Any] = {}

        # Domain toggles - only set if explicitly provided on CLI
        # Use getattr with defaults for subcommand compatibility
        scanners: Dict[str, Dict[str, Any]] = {}
        linters: Dict[str, Dict[str, Any]] = {}

        all_domains = getattr(args, "all", False)
        sca = getattr(args, "sca", False)
        sast = getattr(args, "sast", False)
        iac = getattr(args, "iac", False)
        container = getattr(args, "container", False)
        lint = getattr(args, "lint", False)
        fix = getattr(args, "fix", False)
        images = getattr(args, "images", None)

        if all_domains:
            # Enable all domains including linting
            for domain in ["sca", "sast", "iac", "container"]:
                scanners[domain] = {"enabled": True}
            linters["ruff"] = {"enabled": True}
        else:
            if sca:
                scanners["sca"] = {"enabled": True}
            if sast:
                scanners["sast"] = {"enabled": True}
            if iac:
                scanners["iac"] = {"enabled": True}
            if container:
                scanners["container"] = {"enabled": True}
            if lint:
                linters["ruff"] = {"enabled": True}

        # Container images go into container scanner options
        if images:
            if "container" not in scanners:
                scanners["container"] = {}
            scanners["container"]["enabled"] = True
            scanners["container"]["images"] = images

        if scanners:
            overrides["scanners"] = scanners

        if linters:
            overrides["linters"] = linters

        # Fix mode for linting
        if fix:
            overrides["fix"] = True

        # Fail-on threshold
        fail_on = getattr(args, "fail_on", None)
        if fail_on:
            overrides["fail_on"] = fail_on

        # AI enrichment toggle
        if getattr(args, "ai", False):
            overrides["ai"] = {"enabled": True}

        return overrides

    @staticmethod
    def get_enabled_domains(
        config: LucidScanConfig,
        args: argparse.Namespace,
    ) -> List[ScanDomain]:
        """Determine which scan domains are enabled.

        If CLI flags (--sca, --sast, etc.) are provided, use those.
        Otherwise, use domains enabled in config file.

        Args:
            config: Loaded configuration.
            args: Parsed CLI arguments.

        Returns:
            List of enabled ScanDomain values.
        """
        # Use getattr for subcommand compatibility
        sca = getattr(args, "sca", False)
        sast = getattr(args, "sast", False)
        iac = getattr(args, "iac", False)
        container = getattr(args, "container", False)
        all_domains = getattr(args, "all", False)

        # Check if any domain flags were explicitly set on CLI
        cli_domains_set = any([sca, sast, iac, container, all_domains])

        if cli_domains_set:
            # CLI flags take precedence - use what was explicitly requested
            domains: List[ScanDomain] = []
            if all_domains:
                domains = [
                    ScanDomain.SCA,
                    ScanDomain.SAST,
                    ScanDomain.IAC,
                    ScanDomain.CONTAINER,
                ]
            else:
                if sca:
                    domains.append(ScanDomain.SCA)
                if sast:
                    domains.append(ScanDomain.SAST)
                if iac:
                    domains.append(ScanDomain.IAC)
                if container:
                    domains.append(ScanDomain.CONTAINER)
            return domains

        # Use config file settings
        enabled_domains: List[ScanDomain] = []
        for domain_name in config.get_enabled_domains():
            try:
                enabled_domains.append(ScanDomain(domain_name))
            except ValueError:
                LOGGER.warning(f"Unknown domain in config: {domain_name}")

        return enabled_domains
