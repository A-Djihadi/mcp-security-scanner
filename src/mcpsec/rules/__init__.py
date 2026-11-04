"""Detection rules and the default rule registry."""

from __future__ import annotations

from ..model import RuleRegistry
from ..sources import ReachabilityProvider
from .dependency import DEPUnpinned
from .dependency_registry import (
    DEPKnownVulnerability,
    DEPOutdated,
    DEPUnknown,
)
from .mcp_permissions import (
    MCPAllowAll,
    MCPBroadFilesystem,
    MCPBroadNetwork,
    MCPShellUnrestricted,
)
from .parsing import MCPParseAmbiguous
from .remote import (
    MCPHeaderSecret,
    MCPInsecureTransport,
    MCPRemoteNoAuth,
    MCPUnreachable,
    MCPUnreachableDiagnostic,
)
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
    MCPInsecureTransport(),
    MCPHeaderSecret(),
    MCPRemoteNoAuth(),
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
    "MCPInsecureTransport",
    "MCPHeaderSecret",
    "MCPRemoteNoAuth",
    "MCPUnreachable",
    "MCPUnreachableDiagnostic",
    "SKLShellExecution",
    "SKLRemoteCodeExec",
    "SKLObfuscatedCommand",
    "SKLSqlConcatenation",
    "DEPUnpinned",
    "DEPOutdated",
    "DEPKnownVulnerability",
    "DEPUnknown",
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
    default registry is exactly the offline rule set (ADR-0007). Online rules
    that need a data provider receive it injected here, so the default path
    never constructs a network client. The semantic rule is opt-in: it is
    registered only when an ``embedder`` is explicitly configured (ADR-0008).
    """
    registry = RuleRegistry()
    for rule in _ALL_RULES:
        if online or not getattr(rule, "online", False):
            registry.register(rule)
    if online:
        for rule in _build_online_rules():
            registry.register(rule)
        registry.register(MCPUnreachable(ReachabilityProvider()))
        registry.register(MCPUnreachableDiagnostic())
    if embedder is not None:
        if corpus is None:
            raise ValueError("a corpus is required when an embedder is configured")
        registry.register(SemanticRule(embedder, corpus))
    return registry


def _build_online_rules() -> list:
    """Construct the registry-backed dependency rules with live providers.

    Providers are constructed only under ``--online`` (ADR-0007); construction
    performs no I/O. Each rule receives its provider at construction so
    ``check()`` stays I/O-free and deterministic over provider output.
    """
    from ..sources import NpmProvider, OSVProvider, PopularPackagesProvider, PyPIProvider

    return [
        DEPOutdated(pypi_provider=PyPIProvider(), npm_provider=NpmProvider()),
        DEPKnownVulnerability(OSVProvider()),
        DEPUnknown(PopularPackagesProvider()),
    ]
