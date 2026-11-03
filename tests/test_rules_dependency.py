"""T9 — DEP-unpinned dependency rule."""

from __future__ import annotations

from pathlib import Path

from mcpsec.model import SourceLocation, Target, TargetKind
from mcpsec.parsers import RequirementsParser
from mcpsec.rules import DEPUnpinned

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _dep(name, version_spec, pinned, path="requirements.txt", line=1):
    return Target(
        kind=TargetKind.DEPENDENCY,
        name=name,
        location=SourceLocation(path=path, start_line=line, start_column=1),
        payload={
            "version_spec": version_spec,
            "manifest": path,
            "pinned": pinned,
            "source": f"{name}{version_spec}",
        },
    )


def test_unpinned_dependency_triggers_warning_at_declaration_line():
    rule = DEPUnpinned()
    target = _dep("flask", ">=2.0", False, line=3)
    findings = rule.check(target)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DEP-unpinned"
    assert finding.level == "warning"
    assert finding.location.start_line == 3
    assert "flask" in finding.message
    assert ">=2.0" in finding.message


def test_unpinned_without_spec_names_missing_spec():
    rule = DEPUnpinned()
    finding = rule.check(_dep("django", "", False))[0]
    assert "django" in finding.message
    assert "no version spec" in finding.message


def test_pinned_dependency_triggers_nothing():
    rule = DEPUnpinned()
    assert rule.check(_dep("requests", "==2.31.0", True)) == []
    assert rule.check(_dep("numpy", "===1.24.4", True)) == []


def test_requirements_fixture_flags_only_unpinned():
    rule = DEPUnpinned()
    deps = RequirementsParser().parse(FIXTURES / "requirements.txt")
    flagged = {d.name for d in deps if rule.check(d)}
    assert flagged == {"flask", "django", "pytest"}
