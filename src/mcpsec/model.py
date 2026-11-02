"""Domain model for mcpsec.

This module defines the entities parsers produce, rules consume, and the SARIF
writer projects to output. It is the single vocabulary shared across the
scanner; see `docs/domain-model.md`.

Every entity is an immutable dataclass. ``Target`` is the normalized unit a
parser emits and a rule consumes, discriminated by ``kind``:

* ``mcp_server`` — payload: ``command`` (str|None), ``args`` (list[str]),
  ``env`` (dict[str,str]), ``cwd`` (str|None), ``transport`` ("stdio"|"remote"),
  ``url`` (str|None). Each field carries its own ``SourceLocation`` in
  ``field_locations`` (``"command"``, ``"cwd"``, ``"url"`` → SourceLocation;
  ``"args"`` → tuple[SourceLocation, ...] parallel to the args list; ``"env"`` →
  dict[str, SourceLocation] keyed by env var name).
* ``skill`` — payload: ``frontmatter`` (dict), ``body`` (str), ``body_lines``
  (list[str]). ``field_locations["body"]`` is a tuple[SourceLocation, ...]
  parallel to ``body_lines``.
* ``dependency`` — payload: ``version_spec`` (str), ``manifest`` (str),
  ``pinned`` (bool), ``source`` (str). The target-level ``location`` is the
  declaration line.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Protocol


class TargetKind(str, enum.Enum):
    MCP_SERVER = "mcp_server"
    SKILL = "skill"
    DEPENDENCY = "dependency"


@dataclass(frozen=True)
class SourceLocation:
    """A file path plus 1-based line/column spans and an optional snippet."""

    path: str
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None


@dataclass(frozen=True)
class Target:
    """The normalized unit a parser produces and a rule consumes."""

    kind: TargetKind
    name: str
    location: SourceLocation
    payload: dict[str, Any] = field(default_factory=dict)
    field_locations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """A single detected issue, independent of SARIF."""

    rule_id: str
    level: str  # "error" | "warning" | "note"
    message: str
    location: SourceLocation

    @property
    def fingerprint(self) -> str:
        """Deterministic hash of (rule_id, path, start_line, snippet)."""
        return compute_fingerprint(self.rule_id, self.location)


def compute_fingerprint(rule_id: str, location: SourceLocation) -> str:
    """Stable primary fingerprint for CI baselines (see docs/domain-model.md)."""
    digest = hashlib.sha256()
    for part in (rule_id, location.path, location.start_line, location.snippet):
        digest.update(str(part).encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


class RuleMetadata(Protocol):
    """The declarative part of a rule the writer and registry need."""

    id: str
    level: str  # "error" | "warning" | "note"
    short_description: str


class Rule(RuleMetadata, Protocol):
    """Deterministic static check: maps one Target to zero or more Findings."""

    def check(self, target: Target) -> list[Finding]: ...


class RuleRegistry:
    """An ordered, deduplicated store of rules, iterated in stable id order."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        self._rules[rule.id] = rule

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def __iter__(self) -> Iterator[Rule]:
        return iter(sorted(self._rules.values(), key=lambda r: r.id))

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules


def _finding_key(finding: Finding) -> tuple:
    loc = finding.location
    return (
        finding.rule_id,
        finding.level,
        finding.message,
        loc.path,
        loc.start_line,
        loc.start_column,
        loc.end_line,
        loc.end_column,
        loc.snippet,
    )


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse identical findings, preserving first-seen order."""
    seen: set[tuple] = set()
    result: list[Finding] = []
    for finding in findings:
        key = _finding_key(finding)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort deterministically by (path, line, column, rule id, message)."""
    return sorted(
        findings,
        key=lambda f: (
            f.location.path,
            f.location.start_line or 0,
            f.location.start_column or 0,
            f.rule_id,
            f.message,
        ),
    )
