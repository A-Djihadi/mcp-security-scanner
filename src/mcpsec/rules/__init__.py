"""Detection rules and the default rule registry."""

from __future__ import annotations

from ..model import RuleRegistry
from .dependency import DEPUnpinned
from .mcp_permissions import (
    MCPAllowAll,
    MCPBroadFilesystem,
    MCPBroadNetwork,
    MCPShellUnrestricted,
)
from .skill_patterns import (
    SKLObfuscatedCommand,
    SKLRemoteCodeExec,
    SKLShellExecution,
    SKLSqlConcatenation,
)

_ALL_RULES = [
    MCPShellUnrestricted(),
    MCPAllowAll(),
    MCPBroadNetwork(),
    MCPBroadFilesystem(),
    SKLShellExecution(),
    SKLRemoteCodeExec(),
    SKLObfuscatedCommand(),
    SKLSqlConcatenation(),
    DEPUnpinned(),
]

__all__ = [
    "MCPShellUnrestricted",
    "MCPAllowAll",
    "MCPBroadNetwork",
    "MCPBroadFilesystem",
    "SKLShellExecution",
    "SKLRemoteCodeExec",
    "SKLObfuscatedCommand",
    "SKLSqlConcatenation",
    "DEPUnpinned",
    "build_default_registry",
]


def build_default_registry() -> RuleRegistry:
    """Return a registry populated with every MVP rule (stable id order)."""
    registry = RuleRegistry()
    for rule in _ALL_RULES:
        registry.register(rule)
    return registry
