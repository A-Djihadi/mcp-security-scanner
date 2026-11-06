"""Rule engine: applies the enabled rule set over targets.

The engine owns the enable/disable set and severity threshold (ADR-0002). It
deduplicates identical findings, filters below the severity threshold, and
sorts deterministically by (path, line, column, rule id, message).
"""

from __future__ import annotations

from collections.abc import Iterable

from .model import (
    Finding,
    RuleRegistry,
    Target,
    dedupe_findings,
    sort_findings,
)

_SEVERITY = {"error": 2, "warning": 1, "note": 0}


class RuleEngine:
    def __init__(
        self,
        registry: RuleRegistry,
        *,
        disabled: Iterable[str] = (),
        min_severity: str | None = None,
    ) -> None:
        self._registry = registry
        self._disabled = frozenset(disabled)
        self._min_severity = min_severity

    def run(self, targets: Iterable[Target]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._registry:
            if rule.id in self._disabled:
                continue
            for target in targets:
                findings.extend(rule.check(target))

        findings = dedupe_findings(findings)
        if self._min_severity is not None:
            threshold = _SEVERITY[self._min_severity]
            findings = [f for f in findings if _SEVERITY[f.level] >= threshold]
        return sort_findings(findings)
