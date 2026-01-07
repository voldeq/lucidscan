"""Codebase detection module.

This module provides automatic detection of:
- Programming languages and their versions
- Frameworks and libraries
- Existing tool configurations (linters, type checkers, etc.)
- CI/CD systems

Usage:
    from lucidscan.detection import CodebaseDetector, ProjectContext

    detector = CodebaseDetector()
    context = detector.detect(Path("."))
"""

from lucidscan.detection.detector import CodebaseDetector, ProjectContext, LanguageInfo

__all__ = [
    "CodebaseDetector",
    "ProjectContext",
    "LanguageInfo",
]
