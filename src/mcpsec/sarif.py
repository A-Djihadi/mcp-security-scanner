"""SARIF v2.1.0 writer.

A pure projection of ``Finding`` objects and rule metadata into a single-run
SARIF document. It knows the SARIF schema and nothing else; the domain model
stays SARIF-agnostic (ADR-0004).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from . import __version__
from .model import Finding, RuleMetadata, RuleRegistry, sort_findings


@dataclass(frozen=True)
class _AdhocRule:
    """A minimal rule descriptor for findings whose rule is not registered."""

    id: str
    level: str
    short_description: str = ""
    online: bool = False


class SARIFWriter:
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
    TOOL_NAME = "mcpsec"

    def write(
        self,
        findings: list[Finding],
        rules: RuleRegistry,
        out: Path,
        *,
        online: bool = False,
    ) -> None:
        """Write a SARIF document to ``out`` (creating parent directories)."""
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.dumps(findings, rules, online=online), encoding="utf-8")

    def dumps(
        self, findings: list[Finding], rules: RuleRegistry, *, online: bool = False
    ) -> str:
        return json.dumps(
            self.render(findings, rules, online=online),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        ) + "\n"

    def render(
        self, findings: list[Finding], rules: RuleRegistry, *, online: bool = False
    ) -> dict:
        findings = sort_findings(findings)

        known: dict[str, RuleMetadata] = {rule.id: rule for rule in rules}
        for finding in findings:
            if finding.rule_id not in known:
                known[finding.rule_id] = cast(
                    RuleMetadata, _AdhocRule(finding.rule_id, finding.level)
                )

        rule_list = sorted(known.values(), key=lambda rule: rule.id)
        rule_index = {rule.id: i for i, rule in enumerate(rule_list)}

        driver = {
            "name": self.TOOL_NAME,
            "version": __version__,
            "rules": [
                {
                    "id": rule.id,
                    "shortDescription": {"text": rule.short_description},
                    "defaultConfiguration": {"level": rule.level},
                }
                for rule in rule_list
            ],
        }

        results = []
        for finding in findings:
            result = {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": finding.level,
                "message": {"text": finding.message},
                "locations": [self._location(finding.location)],
                "partialFingerprints": {"primary": finding.fingerprint},
            }
            if getattr(known[finding.rule_id], "online", False):
                result["properties"] = {"mode": "online"}
            if finding.properties:
                result["properties"] = {**(result.get("properties") or {}), **finding.properties}
            results.append(result)

        run: dict = {"tool": {"driver": driver}, "results": results}
        if online:
            run["properties"] = {"mcpsec": {"online": True}}

        return {
            "$schema": self.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [run],
        }

    @staticmethod
    def _location(location) -> dict:
        physical: dict = {"artifactLocation": {"uri": location.path}}
        region: dict = {}
        if location.start_line is not None:
            region["startLine"] = location.start_line
        if location.start_column is not None:
            region["startColumn"] = location.start_column
        if location.end_line is not None:
            region["endLine"] = location.end_line
        if location.end_column is not None:
            region["endColumn"] = location.end_column
        if region:
            physical["region"] = region
        return {"physicalLocation": physical}
