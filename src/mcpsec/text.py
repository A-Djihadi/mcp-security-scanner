"""Human-readable text formatter (one line per finding)."""

from __future__ import annotations

from collections.abc import Iterable

from .model import Finding


def format_finding(finding: Finding) -> str:
    """Format one finding as ``[level] RULE — file:line:col — message``."""
    loc = finding.location
    pos = loc.path
    if loc.start_line is not None:
        pos = f"{pos}:{loc.start_line}"
        if loc.start_column is not None:
            pos = f"{pos}:{loc.start_column}"
    return f"[{finding.level}] {finding.rule_id} — {pos} — {finding.message}"


def format_findings(findings: Iterable[Finding]) -> str:
    """Render findings as newline-separated lines (empty string when none)."""
    lines = [format_finding(f) for f in findings]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"
