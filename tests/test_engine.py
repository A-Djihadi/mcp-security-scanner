"""T6 — rule engine & rule registry (dedup, ordering, enable/disable, threshold)."""

from __future__ import annotations

from mcpsec.engine import RuleEngine
from mcpsec.model import Finding, RuleRegistry, SourceLocation, Target, TargetKind


def _finding(rule_id, level, message, path, line=None, col=None):
    return Finding(
        rule_id=rule_id,
        level=level,
        message=message,
        location=SourceLocation(path=path, start_line=line, start_column=col),
    )


def _target(path="a.json"):
    return Target(
        kind=TargetKind.MCP_SERVER,
        name="srv",
        location=SourceLocation(path=path),
    )


class FakeRule:
    def __init__(self, rule_id, level, findings):
        self.id = rule_id
        self.level = level
        self.short_description = "a fake rule"
        self._findings = list(findings)

    def check(self, target):
        return list(self._findings)


def _registry(*rules):
    reg = RuleRegistry()
    for rule in rules:
        reg.register(rule)
    return reg


def test_rule_yields_expected_findings():
    finding = _finding("R-1", "error", "boom", "a.json", 1)
    engine = RuleEngine(_registry(FakeRule("R-1", "error", [finding])))
    assert engine.run([_target()]) == [finding]


def test_two_rules_producing_same_finding_dedupe():
    finding = _finding("R-1", "error", "same", "a.json", 3)
    engine = RuleEngine(
        _registry(
            FakeRule("R-1", "error", [finding]),
            FakeRule("R-2", "error", [finding]),
        )
    )
    assert engine.run([_target()]) == [finding]


def test_results_sorted_by_path_line_rule_regardless_of_insertion_order():
    engine = RuleEngine(
        _registry(
            FakeRule(
                "R-2",
                "error",
                [_finding("R-2", "error", "m", "z.json", 1)],
            ),
            FakeRule(
                "R-1",
                "error",
                [
                    _finding("R-1", "error", "m", "a.json", 10),
                    _finding("R-1", "error", "m", "a.json", 2),
                ],
            ),
        )
    )
    result = engine.run([_target()])
    keys = [
        (f.location.path, f.location.start_line, f.rule_id) for f in result
    ]
    assert keys == [
        ("a.json", 2, "R-1"),
        ("a.json", 10, "R-1"),
        ("z.json", 1, "R-2"),
    ]


def test_disabled_rules_contribute_no_findings():
    engine = RuleEngine(
        _registry(
            FakeRule("R-1", "error", [_finding("R-1", "error", "m", "a.json", 1)]),
            FakeRule("R-2", "warning", [_finding("R-2", "warning", "m", "a.json", 1)]),
        ),
        disabled={"R-1"},
    )
    result = engine.run([_target()])
    assert [f.rule_id for f in result] == ["R-2"]


def test_severity_threshold_filters_lower_severity():
    findings = [
        _finding("R-1", "error", "e", "a.json", 1),
        _finding("R-2", "warning", "w", "a.json", 2),
        _finding("R-3", "note", "n", "a.json", 3),
    ]
    reg = _registry(
        FakeRule("R-1", "error", [findings[0]]),
        FakeRule("R-2", "warning", [findings[1]]),
        FakeRule("R-3", "note", [findings[2]]),
    )

    at_warning = RuleEngine(reg, min_severity="warning").run([_target()])
    assert {f.rule_id for f in at_warning} == {"R-1", "R-2"}

    at_error = RuleEngine(reg, min_severity="error").run([_target()])
    assert [f.rule_id for f in at_error] == ["R-1"]


def test_run_empty_targets_returns_empty():
    engine = RuleEngine(
        _registry(FakeRule("R-1", "error", [_finding("R-1", "error", "m", "a.json", 1)]))
    )
    assert engine.run([]) == []
