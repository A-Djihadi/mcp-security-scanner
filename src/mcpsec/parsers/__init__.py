"""Format parsers: one adapter per file format, each emitting ``Target`` lists."""

from __future__ import annotations

from .mcp_config import ClaudeDesktopConfigParser, McpConfigParser
from .package_json import PackageJsonParser
from .pyproject import PyprojectParser
from .requirements import RequirementsParser

__all__ = [
    "ClaudeDesktopConfigParser",
    "McpConfigParser",
    "PackageJsonParser",
    "PyprojectParser",
    "RequirementsParser",
]
