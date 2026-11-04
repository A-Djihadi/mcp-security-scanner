"""Format parsers: one adapter per file format, each emitting ``Target`` lists."""

from __future__ import annotations

from .mcp_config import ClaudeDesktopConfigParser, McpConfigParser
from .package_json import PackageJsonParser
from .pyproject import PyprojectParser
from .python_source import PythonSourceParser
from .requirements import RequirementsParser
from .skill_markdown import SkillMarkdownParser
from .smithery_yaml import SmitheryYamlParser

__all__ = [
    "ClaudeDesktopConfigParser",
    "McpConfigParser",
    "PackageJsonParser",
    "PyprojectParser",
    "PythonSourceParser",
    "RequirementsParser",
    "SkillMarkdownParser",
    "SmitheryYamlParser",
]
