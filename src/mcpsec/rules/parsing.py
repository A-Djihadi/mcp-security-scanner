"""Parse-diagnostic rules.

A parser records recoverable ambiguity on a target; these rules surface it as a
note-level finding so a scan never silently swallows a target it could not fully
resolve. They do no I/O and hold no state (ADR-0002).
"""

from __future__ import annotations

from ..model import Finding, Target, TargetKind


class MCPParseAmbiguous:
    """Flag an MCP target whose command could not be statically resolved."""

    id = "MCP-parse-ambiguous"
    level = "note"
    short_description = (
        "MCP server command could not be statically resolved from config."
    )

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        if not target.payload.get("parse_ambiguous"):
            return []
        reason = target.payload.get("parse_note") or "unresolvable command"
        location = target.field_locations.get("commandFunction") or target.location
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'server "{target.name}" command could not be statically '
                    f"resolved ({reason})"
                ),
                location=location,
            )
        ]
