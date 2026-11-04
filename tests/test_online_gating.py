"""T11 — online rule gating: `--online` flag, registry filtering, SARIF mode."""

from __future__ import annotations

import socket
import urllib.request
from pathlib import Path

import pytest

from mcpsec import cli, rules
from mcpsec.model import Finding, RuleRegistry, SourceLocation
from mcpsec.sarif import SARIFWriter

FIXTURES = Path(__file__).resolve().parent / "fixtures"
E2E = FIXTURES / "e2e"


class _OfflineRule:
    id = "R-offline"
    level = "note"
    short_description = "an offline rule"
    online = False

    def check(self, target):
        return []


class _OnlineRule:
    id = "R-online"
    level = "note"
    short_description = "an online rule"
    online = True

    def check(self, target):
        return []


def _finding(rule_id, level, message, path="a.json", line=1):
    return Finding(
        rule_id=rule_id,
        level=level,
        message=message,
        location=SourceLocation(path=path, start_line=line),
    )


def _registry(*rules_):
    reg = RuleRegistry()
    for rule in rules_:
        reg.register(rule)
    return reg


def _run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_online_rule_absent_by_default_present_with_flag(monkeypatch):
    monkeypatch.setattr(rules, "_ALL_RULES", [_OfflineRule(), _OnlineRule()])
    offline = rules.build_default_registry()
    assert "R-offline" in offline
    assert "R-online" not in offline

    online = rules.build_default_registry(online=True)
    assert "R-online" in online
    assert "R-offline" in online


def test_scan_help_lists_online_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "--help"])
    assert exc.value.code == 0
    assert "--online" in capsys.readouterr().out


def test_offline_scan_never_opens_socket(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    touched = []

    def _boom(*args, **kwargs):
        touched.append((args, kwargs))
        raise AssertionError("network touched during offline scan")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    code, out, _ = _run(["scan", str(tmp_path), "--format", "text"], capsys)
    assert code == 0
    assert "DEP-unpinned" in out
    assert touched == []


def test_online_finding_carries_mode_property():
    reg = _registry(_OfflineRule(), _OnlineRule())
    findings = [
        _finding("R-offline", "note", "offline", line=1),
        _finding("R-online", "note", "online", line=2),
    ]
    doc = SARIFWriter().render(findings, reg, online=True)
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert results["R-online"]["properties"] == {"mode": "online"}
    assert "properties" not in results["R-offline"]


def test_run_records_online_true_when_online_and_absent_otherwise():
    reg = _registry(_OfflineRule())
    online = SARIFWriter().render([], reg, online=True)
    assert online["runs"][0]["properties"]["mcpsec"]["online"] is True

    offline = SARIFWriter().render([], reg, online=False)
    assert "properties" not in offline["runs"][0]


def test_online_flag_with_rules_and_exclude(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    class DepOutdatedRule:
        id = "DEP-outdated"
        level = "note"
        short_description = "online dependency rule"
        online = True

        def check(self, target):
            return [Finding("DEP-outdated", "note", "outdated", target.location)]

    reg = RuleRegistry()
    reg.register(DepOutdatedRule())
    monkeypatch.setattr(cli, "build_default_registry", lambda *, online=False: reg)

    code, out, _ = _run(
        [
            "scan",
            str(tmp_path),
            "--format",
            "text",
            "--online",
            "--rules",
            "DEP-outdated",
            "--exclude-rule",
            "DEP-outdated",
        ],
        capsys,
    )
    assert out == ""
    assert code == 0
