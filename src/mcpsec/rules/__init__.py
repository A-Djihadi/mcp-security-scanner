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
from .parsing import MCPParseAmbiguous
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
    MCPParseAmbiguous(),
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
    "MCPParseAmbiguous",
    "build_default_registry",
]


def build_default_registry(*, online: bool = False) -> RuleRegistry:
    """Return a registry populated with every MVP rule (stable id order).

    Online rules (``online=True``) are included only when ``online=True``; the
    default registry is exactly the offline phase-1 rule set (ADR-0007).
    """
    registry = RuleRegistry()
    for rule in _ALL_RULES:
        if online or not getattr(rule, "online", False):
            registry.register(rule)
    return registry
