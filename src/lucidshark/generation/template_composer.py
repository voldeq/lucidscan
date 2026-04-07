"""Template-based configuration composer for lucidshark init.

Loads pre-built language templates from package data and merges them
to produce a complete lucidshark.yml configuration.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from lucidshark.detection.detector import ProjectContext

# Language name (from detection) → template filename (without .yml)
LANGUAGE_TEMPLATE_MAP: Dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "go": "go",
    "rust": "rust",
    "java": "java",
    "kotlin": "kotlin",
    "csharp": "csharp",
    "c": "c",
    "c++": "cpp",
    "scala": "scala",
    "swift": "swift",
    "ruby": "ruby",
    "php": "php",
}


def load_template(language: str) -> Optional[Dict[str, Any]]:
    """Load a language template YAML file from package data.

    Args:
        language: Language name as detected (e.g., "python", "c++").

    Returns:
        Parsed YAML dict, or None if no template exists for the language.
    """
    template_name = LANGUAGE_TEMPLATE_MAP.get(language)
    if template_name is None:
        return None

    filename = f"{template_name}.yml"

    # Try importlib.resources (works for pip install and PyInstaller)
    try:
        from importlib.resources import (  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
            files,
        )

        data_dir = files("lucidshark").joinpath(f"data/templates/{filename}")
        content = data_dir.read_text(encoding="utf-8")
        return yaml.safe_load(content)
    except (FileNotFoundError, TypeError):
        pass

    # Fall back to filesystem path relative to this module (development)
    module_dir = Path(__file__).parent.parent / "data" / "templates"
    template_path = module_dir / filename
    if template_path.exists():
        content = template_path.read_text(encoding="utf-8")
        return yaml.safe_load(content)

    return None


def merge_templates(templates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple language template dicts into a single config.

    Merge strategy:
    - pipeline domains: union of all tools (deduplicated by tool name)
    - fail_on: take the first value for each domain key
    - exclude: union of all patterns (deduplicated, order preserved)
    - For scalar config (threshold, min_lines): take the first value

    Args:
        templates: List of parsed template dicts.

    Returns:
        Merged config dict with pipeline, fail_on, and exclude sections.
    """
    if not templates:
        return {"pipeline": {}, "fail_on": {}, "exclude": []}

    merged_pipeline: Dict[str, Any] = {}
    merged_fail_on: Dict[str, str] = {}
    merged_exclude: List[str] = []
    seen_exclude: set = set()

    for template in templates:
        pipeline = template.get("pipeline", {})
        fail_on = template.get("fail_on", {})
        exclude = template.get("exclude", [])

        # Merge pipeline domains
        for domain, domain_config in pipeline.items():
            if domain not in merged_pipeline:
                merged_pipeline[domain] = copy.deepcopy(domain_config)
            else:
                _merge_domain(merged_pipeline[domain], domain_config, domain)

        # Merge fail_on (first value wins)
        for key, value in fail_on.items():
            if key not in merged_fail_on:
                merged_fail_on[key] = value

        # Merge exclude patterns (deduplicate, preserve order)
        for pattern in exclude:
            if pattern not in seen_exclude:
                seen_exclude.add(pattern)
                merged_exclude.append(pattern)

    return {
        "pipeline": merged_pipeline,
        "fail_on": merged_fail_on,
        "exclude": merged_exclude,
    }


def _merge_domain(
    existing: Dict[str, Any],
    incoming: Dict[str, Any],
    domain: str,
) -> None:
    """Merge an incoming domain config into an existing one.

    Tools are unioned (deduplicated by name). Scalar fields (threshold,
    min_lines, etc.) keep the existing value.
    """
    # Merge tools list
    if "tools" in incoming:
        existing_tools = existing.get("tools", [])
        incoming_tools = incoming.get("tools", [])
        existing["tools"] = _merge_tool_lists(existing_tools, incoming_tools, domain)


def _merge_tool_lists(
    existing: List[Any],
    incoming: List[Any],
    domain: str,
) -> List[Any]:
    """Merge two tool lists, deduplicating by tool identity.

    For security tools, identity is (name, frozenset(domains)).
    For all other tools, identity is just the name.

    Args:
        existing: Existing tools list.
        incoming: Incoming tools list.
        domain: Domain name (used to determine dedup strategy).

    Returns:
        Merged tools list.
    """
    result = list(existing)

    if domain == "security":
        # Deduplicate by (name, domains) tuple
        seen = set()
        for tool in existing:
            name = tool["name"] if isinstance(tool, dict) else tool
            domains = (
                tuple(sorted(tool.get("domains", []))) if isinstance(tool, dict) else ()
            )
            seen.add((name, domains))

        for tool in incoming:
            name = tool["name"] if isinstance(tool, dict) else tool
            domains = (
                tuple(sorted(tool.get("domains", []))) if isinstance(tool, dict) else ()
            )
            if (name, domains) not in seen:
                seen.add((name, domains))
                result.append(copy.deepcopy(tool))
    else:
        # Deduplicate by name only
        seen_names = set()
        for tool in existing:
            name = tool["name"] if isinstance(tool, dict) else tool
            seen_names.add(name)

        for tool in incoming:
            name = tool["name"] if isinstance(tool, dict) else tool
            if name not in seen_names:
                seen_names.add(name)
                result.append(copy.deepcopy(tool))

    return result


class TemplateComposer:
    """Composes lucidshark.yml from detected project context and language templates."""

    def compose(self, context: ProjectContext) -> str:
        """Compose a complete lucidshark.yml YAML string.

        Args:
            context: Detected project context from CodebaseDetector.

        Returns:
            YAML string ready to write as lucidshark.yml.
        """
        config = self.compose_config(context)
        return self._to_yaml(config)

    def compose_config(self, context: ProjectContext) -> Dict[str, Any]:
        """Compose configuration dict.

        Args:
            context: Detected project context.

        Returns:
            Complete config dict with version, project, pipeline, fail_on, exclude.
        """
        language_names = [lang.name for lang in context.languages]

        # Load templates for each detected language
        templates = []
        for lang_name in language_names:
            template = load_template(lang_name)
            if template is not None:
                templates.append(template)

        # Merge templates
        merged = merge_templates(templates)

        # Build complete config
        config: Dict[str, Any] = {
            "version": 1,
            "project": {
                "name": context.root.name,
                "languages": language_names,
            },
        }

        if merged["pipeline"]:
            config["pipeline"] = merged["pipeline"]

        if merged["fail_on"]:
            config["fail_on"] = merged["fail_on"]

        if merged["exclude"]:
            config["exclude"] = merged["exclude"]

        return config

    def write(
        self,
        context: ProjectContext,
        output_path: Optional[Path] = None,
    ) -> Path:
        """Compose and write lucidshark.yml file.

        Args:
            context: Detected project context.
            output_path: Output file path (default: project_root/lucidshark.yml).

        Returns:
            Path to the written file.
        """
        if output_path is None:
            output_path = context.root / "lucidshark.yml"

        content = self.compose(context)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _to_yaml(self, config: Dict[str, Any]) -> str:
        """Convert config dict to YAML string with header comment."""
        header = "# LucidShark Configuration\n# Generated by lucidshark init\n\n"

        yaml_content = yaml.dump(
            config,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        return header + yaml_content
