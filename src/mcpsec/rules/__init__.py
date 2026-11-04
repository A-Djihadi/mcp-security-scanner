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
from .semantic import CorpusAnchor, SemanticCorpus, SemanticRule
from .skill_patterns import (
    SKLObfuscatedCommand,
    SKLRemoteCodeExec,
    SKLShellExecution,
    SKLSqlConcatenation,
)
from .taint import FLOWCodeEval, FLOWShellInjection, FLOWSqlInjection

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
    FLOWShellInjection(),
    FLOWSqlInjection(),
    FLOWCodeEval(),
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
    "FLOWShellInjection",
    "FLOWSqlInjection",
    "FLOWCodeEval",
    "CorpusAnchor",
    "SemanticCorpus",
    "SemanticRule",
    "build_default_registry",
]


def build_default_registry(*, online: bool = False, embedder=None, corpus=None) -> RuleRegistry:
    """Return a registry populated with every MVP rule (stable id order).

    Online rules (``online=True``) are included only when ``online=True``; the
    default registry is exactly the offline phase-1 rule set (ADR-0007). The
    semantic rule is opt-in: it is registered only when an ``embedder`` is
    explicitly configured (ADR-0008).
    """
    registry = RuleRegistry()
    for rule in _ALL_RULES:
        if online or not getattr(rule, "online", False):
            registry.register(rule)
    if embedder is not None:
        if corpus is None:
            raise ValueError("a corpus is required when an embedder is configured")
        registry.register(SemanticRule(embedder, corpus))
    return registry
