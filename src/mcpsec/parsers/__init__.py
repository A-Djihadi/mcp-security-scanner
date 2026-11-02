"""Format parsers: one adapter per file format, each emitting ``Target`` lists."""

from __future__ import annotations

from .mcp_config import ClaudeDesktopConfigParser, McpConfigParser

__all__ = [
    "ClaudeDesktopConfigParser",
    "McpConfigParser",
]
