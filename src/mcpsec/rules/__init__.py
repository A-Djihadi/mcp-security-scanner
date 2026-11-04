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
from .semantic import CorpusAnchor, SemanticCorpus, SemanticRule
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
    "CorpusAnchor",
    "SemanticCorpus",
    "SemanticRule",
    "build_default_registry",
]


def build_default_registry(*, embedder=None, corpus=None) -> RuleRegistry:
    """Return a registry populated with every MVP rule (stable id order).

    The semantic rule is opt-in: it is registered only when an ``embedder`` is
    explicitly configured (ADR-0008). A default scan constructs no embedder and
    never touches the semantic rule.
    """
    registry = RuleRegistry()
    for rule in _ALL_RULES:
        registry.register(rule)
    if embedder is not None:
        if corpus is None:
            raise ValueError("a corpus is required when an embedder is configured")
        registry.register(SemanticRule(embedder, corpus))
    return registry
