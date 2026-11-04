"""T21 — default local embedder integration test.

Exercises the real ONNX sentence-transformer against the golden fixture. It is
marked to skip when the ``[semantic]`` extra is not installed or the pinned
model cannot be obtained, so the base ``uv run pytest`` stays green without the
optional group.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpsec import cli
from mcpsec.embedder import MODEL_NAME, MODEL_REVISION
from mcpsec.parsers import SkillMarkdownParser
from mcpsec.rules.semantic import SemanticRule

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "semantic"


def _load_or_skip():
    pytest.importorskip("onnxruntime")
    pytest.importorskip("tokenizers")
    from mcpsec.corpus import DEFAULT_CORPUS
    from mcpsec.embedder import SemanticBackendError, load_default_embedder

    try:
        embedder = load_default_embedder()
    except SemanticBackendError as exc:
        pytest.skip(f"default embedder unavailable: {exc}")
    return embedder, DEFAULT_CORPUS


def _skill_target(path: Path):
    return SkillMarkdownParser().parse(path)[0]


def test_default_embedder_flags_adversarial_skill():
    embedder, corpus = _load_or_skip()
    rule = SemanticRule(embedder, corpus)
    target = _skill_target(FIXTURES / "malicious" / "SKILL.md")

    findings = rule.check(target)
    assert [f.rule_id for f in findings] == ["SKL-semantic-malicious"]
    assert findings[0].level == "warning"


def test_default_embedder_ignores_benign_skill():
    embedder, corpus = _load_or_skip()
    rule = SemanticRule(embedder, corpus)
    target = _skill_target(FIXTURES / "benign" / "SKILL.md")
    assert rule.check(target) == []


def test_finding_records_pinned_model_and_corpus_version():
    embedder, corpus = _load_or_skip()
    rule = SemanticRule(embedder, corpus)
    target = _skill_target(FIXTURES / "malicious" / "SKILL.md")

    findings = rule.check(target)
    assert len(findings) == 1
    properties = findings[0].properties
    assert properties["model"] == MODEL_NAME
    assert properties["model_version"] == MODEL_REVISION
    assert properties["corpus_version"] == corpus.version


def test_full_scan_with_semantic_flag_emits_sarif_finding(capsys):
    _load_or_skip()  # skip here when the extra/model is unavailable
    code = cli.main(["scan", str(FIXTURES), "--semantic", "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    results = doc["runs"][0]["results"]

    semantic = [r for r in results if r["ruleId"] == "SKL-semantic-malicious"]
    assert len(semantic) == 1
    assert code == 0  # warning-level finding; default fail-on is error
    uri = semantic[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("malicious/SKILL.md")
    assert semantic[0]["properties"]["model_version"] == MODEL_REVISION
    assert semantic[0]["properties"]["corpus_version"] == "1"
