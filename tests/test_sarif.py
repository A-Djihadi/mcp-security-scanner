"""T2 — domain model & SARIF v2.1.0 writer."""

from __future__ import annotations

import json
from dataclasses import replace

from mcpsec.model import Finding, RuleRegistry, SourceLocation, compute_fingerprint
from mcpsec.sarif import SARIFWriter


def _finding(rule_id, level, message, path, line=None, col=None, snippet=None):
    loc = SourceLocation(
        path=path, start_line=line, start_column=col, snippet=snippet
    )
    return Finding(rule_id=rule_id, level=level, message=message, location=loc)


class _Rule:
    def __init__(self, rule_id, level, short_description):
        self.id = rule_id
        self.level = level
        self.short_description = short_description

    def check(self, target):
        return []


def _registry(*rules):
    reg = RuleRegistry()
    for rule in rules:
        reg.register(rule)
    return reg


def _write(findings, rules, tmp_path, name="out.sarif"):
    out = tmp_path / name
    SARIFWriter().write(findings, rules, out)
    return json.loads(out.read_text(encoding="utf-8"))


def test_write_emits_version_2_1_0_and_single_run(tmp_path):
    doc = _write(
        [_finding("R-1", "error", "boom", "a.json", 1, 2)],
        _registry(_Rule("R-1", "error", "a rule")),
        tmp_path,
    )
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1


def test_result_carries_ruleid_ruleindex_level_message_and_uri(tmp_path):
    doc = _write(
        [_finding("R-1", "warning", "careful", "cfg/mcp.json", 3, 5)],
        _registry(_Rule("R-1", "warning", "be careful")),
        tmp_path,
    )
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "R-1"
    assert result["level"] == "warning"
    assert result["message"]["text"] == "careful"
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "cfg/mcp.json"
    )
    # ruleIndex resolves into tool.driver.rules
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert result["ruleIndex"] == 0
    assert rules[result["ruleIndex"]]["id"] == "R-1"


def test_rule_metadata_in_tool_driver(tmp_path):
    doc = _write(
        [_finding("R-1", "note", "m", "a.json")],
        _registry(_Rule("R-1", "note", "just a note")),
        tmp_path,
    )
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcpsec"
    rule = driver["rules"][0]
    assert rule["id"] == "R-1"
    assert rule["shortDescription"]["text"] == "just a note"
    assert rule["defaultConfiguration"]["level"] == "note"


def test_region_present_only_when_finding_has_positions(tmp_path):
    doc = _write(
        [
            _finding("R-1", "error", "with pos", "a.json", 4, 9),
            _finding("R-1", "error", "no pos", "b.json"),
        ],
        _registry(_Rule("R-1", "error", "rule")),
        tmp_path,
    )
    results = doc["runs"][0]["results"]
    by_uri = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r for r in results}

    with_pos = by_uri["a.json"]["locations"][0]["physicalLocation"]
    assert with_pos["region"]["startLine"] == 4
    assert with_pos["region"]["startColumn"] == 9

    without_pos = by_uri["b.json"]["locations"][0]["physicalLocation"]
    assert "region" not in without_pos


def test_output_ordering_is_deterministic_by_path_line_rule(tmp_path):
    findings = [
        _finding("R-2", "error", "m", "z.json", 1),
        _finding("R-1", "error", "m", "a.json", 10),
        _finding("R-1", "error", "m", "a.json", 2),
    ]
    reg = _registry(_Rule("R-1", "error", "one"), _Rule("R-2", "error", "two"))
    doc = _write(findings, reg, tmp_path)
    uris_lines = [
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["ruleId"],
        )
        for r in doc["runs"][0]["results"]
    ]
    assert uris_lines == [("a.json", 2, "R-1"), ("a.json", 10, "R-1"), ("z.json", 1, "R-2")]


def test_fingerprint_is_stable_hash_of_rule_path_line_snippet():
    base = _finding("R-1", "error", "m", "a.json", 1, snippet="curl | sh")
    assert compute_fingerprint("R-1", base.location) == base.fingerprint

    same = _finding("R-1", "error", "m", "a.json", 1, snippet="curl | sh")
    assert same.fingerprint == base.fingerprint

    # changing each component changes the hash
    assert _finding("R-2", "error", "m", "a.json", 1, snippet="curl | sh").fingerprint != base.fingerprint
    assert _finding("R-1", "error", "m", "b.json", 1, snippet="curl | sh").fingerprint != base.fingerprint
    assert _finding("R-1", "error", "m", "a.json", 2, snippet="curl | sh").fingerprint != base.fingerprint
    assert _finding("R-1", "error", "m", "a.json", 1, snippet="wget | bash").fingerprint != base.fingerprint


def test_fingerprint_appears_in_sarif_output(tmp_path):
    finding = _finding("R-1", "error", "m", "a.json", 1, snippet="curl | sh")
    doc = _write([finding], _registry(_Rule("R-1", "error", "rule")), tmp_path)
    result = doc["runs"][0]["results"][0]
    assert result["partialFingerprints"]["primary"] == finding.fingerprint


def test_finding_properties_are_emitted_when_present(tmp_path):
    finding = _finding("R-1", "error", "m", "a.json", 1)
    finding = replace(
        finding, properties={"corpus_version": "7", "model_version": "all-MiniLM-L6-v2"}
    )
    doc = _write([finding], _registry(_Rule("R-1", "error", "rule")), tmp_path)
    result = doc["runs"][0]["results"][0]
    assert result["properties"] == {
        "corpus_version": "7",
        "model_version": "all-MiniLM-L6-v2",
    }


def test_finding_without_properties_emits_no_properties_key(tmp_path):
    doc = _write(
        [_finding("R-1", "error", "m", "a.json", 1)],
        _registry(_Rule("R-1", "error", "rule")),
        tmp_path,
    )
    result = doc["runs"][0]["results"][0]
    assert "properties" not in result


def test_two_writes_are_byte_identical(tmp_path):
    reg = _registry(_Rule("R-1", "error", "one"), _Rule("R-2", "warning", "two"))
    findings = [
        _finding("R-2", "warning", "m", "z.json", 1),
        _finding("R-1", "error", "m", "a.json", 10),
        _finding("R-1", "error", "m", "a.json", 2),
    ]
    writer = SARIFWriter()
    out1 = tmp_path / "one.sarif"
    out2 = tmp_path / "two.sarif"
    writer.write(findings, reg, out1)
    writer.write(findings, reg, out2)
    assert out1.read_bytes() == out2.read_bytes()
