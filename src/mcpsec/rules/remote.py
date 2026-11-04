"""Remote MCP server rules.

T15 (offline, deterministic): ``MCP-insecure-transport``, ``MCP-header-secret``,
and ``MCP-remote-no-auth`` — pure checks over a remote ``mcp_server`` target, no
I/O, no state. T16 (online): ``MCP-unreachable`` probes the remote ``url`` via
the reachability provider from ``mcpsec.sources``.

Every header convention and secret pattern here is a heuristic against
real-world client conventions and is marked "to verify" rather than asserted as
fact (ADR-0007 / coder brief: do not invent format facts).
"""

from __future__ import annotations

import re
from typing import Protocol
from urllib.parse import urlsplit

from ..model import Finding, Target, TargetKind
from ..sources import DataUnavailable


class _ReachabilityProbe(Protocol):
    """A reachability provider: ``probe(url) -> "reachable" | "unreachable"``."""

    def probe(self, url: str) -> str: ...

# Auth-bearing header names (lowercased). These are the headers that, in the
# common MCP client conventions, carry a credential. The exact set is "to
# verify" per client.
_AUTH_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "x-api-token",
        "api-token",
        "x-auth-token",
        "x-access-token",
        "access-token",
        "cookie",
        "set-cookie",
    }
)

# Secret-looking literal prefixes in a header value. Lengths are lower bounds to
# avoid flagging incidental substrings; the exact formats are "to verify".
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),  # OpenAI-style — to verify
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),  # GitHub PAT — to verify
    re.compile(r"\bgho_[A-Za-z0-9]{20,}"),  # GitHub OAuth token — to verify
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),  # fine-grained PAT — to verify
    re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}"),  # Slack tokens — to verify
)

# A value that references an environment variable (``$NAME``, ``${NAME}``,
# ``%NAME%``) is treated as injected-at-runtime, not a hardcoded secret. The
# exact templating conventions per client are "to verify".
_ENV_REFERENCE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%"
)


def _is_placeholder(value: str) -> bool:
    return bool(_ENV_REFERENCE.search(value))


def _header_is_secret(name: str, value: str) -> bool:
    """Return True when a header carries a hardcoded secret literal."""
    value = value.strip()
    if not value or _is_placeholder(value):
        return False
    if name.strip().lower() in _AUTH_HEADERS:
        return True
    return any(pattern.search(value) for pattern in _SECRET_PATTERNS)


def _has_auth_header(headers: dict) -> bool:
    return any(name.strip().lower() in _AUTH_HEADERS for name in headers)


def _header_locations(target: Target) -> dict:
    locs = target.field_locations.get("headers")
    return locs if isinstance(locs, dict) else {}


class MCPInsecureTransport:
    """Flag a remote server reached over plaintext ``http://``."""

    id = "MCP-insecure-transport"
    level = "error"
    short_description = "Remote MCP server uses plaintext HTTP transport."
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        if target.payload.get("transport") != "remote":
            return []
        url = target.payload.get("url")
        if not isinstance(url, str) or not url:
            return []
        scheme = urlsplit(url).scheme.lower()
        if scheme != "http":
            return []
        location = target.field_locations.get("url") or target.location
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'server "{target.name}" uses plaintext HTTP transport '
                    f'(url "{url}")'
                ),
                location=location,
            )
        ]


class MCPHeaderSecret:
    """Flag a hardcoded secret literal in a remote server's headers."""

    id = "MCP-header-secret"
    level = "warning"
    short_description = "MCP server config stores a secret in headers."
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        headers = target.payload.get("headers")
        if not isinstance(headers, dict):
            return []
        locations = _header_locations(target)
        findings: list[Finding] = []
        for name, value in headers.items():
            if not isinstance(value, str) or not _header_is_secret(name, value):
                continue
            location = locations.get(name) or target.location
            findings.append(
                Finding(
                    rule_id=self.id,
                    level=self.level,
                    message=(
                        f'server "{target.name}" stores a secret in header '
                        f'"{name}"'
                    ),
                    location=location,
                )
            )
        return findings


class MCPRemoteNoAuth:
    """Flag a remote server with no auth-bearing header (heuristic)."""

    id = "MCP-remote-no-auth"
    level = "note"
    short_description = (
        "Remote MCP server has no auth-bearing header (to verify per client)."
    )
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        if target.payload.get("transport") != "remote":
            return []
        headers = target.payload.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        if _has_auth_header(headers):
            return []
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'server "{target.name}" is remote with no auth-bearing '
                    f"header (to verify: client auth convention)"
                ),
                location=target.location,
            )
        ]


class MCPUnreachable:
    """Flag a remote server whose endpoint cannot be reached (online)."""

    id = "MCP-unreachable"
    level = "note"
    short_description = "Remote MCP server endpoint is unreachable."
    online = True

    def __init__(self, provider: _ReachabilityProbe) -> None:
        self._provider = provider

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        if target.payload.get("transport") != "remote":
            return []
        url = target.payload.get("url")
        if not isinstance(url, str) or not url:
            return []
        try:
            state = self._provider.probe(url)
        except DataUnavailable as exc:
            return [
                Finding(
                    rule_id="MCP-unreachable-diagnostic",
                    level="note",
                    message=(
                        f'server "{target.name}" reachability could not be '
                        f"determined ({exc})"
                    ),
                    location=target.field_locations.get("url") or target.location,
                )
            ]
        if state != "unreachable":
            return []
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=f'server "{target.name}" is unreachable (url "{url}")',
                location=target.field_locations.get("url") or target.location,
            )
        ]


class MCPUnreachableDiagnostic:
    """Metadata for the reachability diagnostic (no independent check)."""

    id = "MCP-unreachable-diagnostic"
    level = "note"
    short_description = "Remote MCP server reachability could not be determined."
    online = True

    def check(self, target: Target) -> list[Finding]:
        return []
