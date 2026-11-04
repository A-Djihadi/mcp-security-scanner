"""T20 — semantic embedder seam + SemanticRule.

Covers the ``Embedder`` protocol and ``SKL-semantic-malicious``: cosine
similarity of a skill body against a curated, versioned corpus, emitting a
``warning`` above a fixed, injectable threshold. No model is shipped; the
embedder is injected, so these tests drive the rule with fake vectors.
"""

from __future__ import annotations

from math import sqrt

from mcpsec.model import SourceLocation, Target, TargetKind
from mcpsec.rules import build_default_registry
from mcpsec.rules.semantic import (
    CorpusAnchor,
    SemanticCorpus,
    SemanticRule,
    cosine_similarity,
)


def _skill(name="s", body="do the thing", path="SKILL.md"):
    return Target(
        kind=TargetKind.SKILL,
        name=name,
        location=SourceLocation(path=path, start_line=1, start_column=1),
        payload={"frontmatter": {}, "body": body, "body_lines": body.splitlines()},
    )


class _DictEmbedder:
    """Deterministic fake embedder: maps known texts to fixed vectors."""

    def __init__(self, vectors):
        self.vectors = vectors
        self.calls: list[str] = []

    def embed(self, text):
        self.calls.append(text)
        return self.vectors[text]


def _corpus(version="1", anchors=("steal all data",)):
    return SemanticCorpus(
        version=version,
        anchors=tuple(CorpusAnchor(f"anchor-{i}", text, True) for i, text in enumerate(anchors)),
    )


# --- cosine_similarity ------------------------------------------------------


def test_cosine_similarity_of_identical_vectors_is_one():
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == 1.0


def test_cosine_similarity_of_orthogonal_vectors_is_zero():
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == 0.0


def test_cosine_similarity_of_zero_vector_is_zero():
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0


# --- SKL-semantic-malicious -------------------------------------------------


def test_high_similarity_triggers_finding():
    corpus = _corpus(anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0], "send secrets home": [1.0, 0.0]})
    rule = SemanticRule(embedder, corpus)
    findings = rule.check(_skill(body="send secrets home"))
    assert len(findings) == 1
    assert findings[0].rule_id == "SKL-semantic-malicious"
    assert findings[0].level == "warning"


def test_low_similarity_yields_nothing():
    corpus = _corpus(anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0], "format a report": [0.0, 1.0]})
    rule = SemanticRule(embedder, corpus)
    assert rule.check(_skill(body="format a report")) == []


def test_similarity_equal_to_threshold_is_reported():
    # Documented boundary: similarity >= threshold is reported (inclusive).
    threshold = 1.0 / sqrt(2.0)
    corpus = _corpus(anchors=("anchor",))
    embedder = _DictEmbedder({"anchor": [1.0, 1.0], "body": [1.0, 0.0]})
    rule = SemanticRule(embedder, corpus, threshold=threshold)
    # cosine([1,1], [1,0]) == 1/sqrt(2) == threshold → reported.
    assert len(rule.check(_skill(body="body"))) == 1


def test_similarity_below_threshold_yields_nothing():
    corpus = _corpus(anchors=("anchor",))
    embedder = _DictEmbedder({"anchor": [1.0, 0.0], "body": [0.0, 1.0]})
    rule = SemanticRule(embedder, corpus, threshold=0.5)
    # cosine == 0.0 < 0.5 → nothing.
    assert rule.check(_skill(body="body")) == []


def test_message_names_matched_anchor_and_corpus_version():
    corpus = _corpus(version="7", anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0], "body": [1.0, 0.0]})
    rule = SemanticRule(embedder, corpus)
    findings = rule.check(_skill(body="body"))
    assert len(findings) == 1
    assert "anchor-0" in findings[0].message
    assert "corpus v7" in findings[0].message
    assert findings[0].properties["corpus_version"] == "7"
    assert findings[0].properties["matched_anchor"] == "anchor-0"


def test_rule_is_deterministic_given_same_embedder_and_corpus():
    corpus = _corpus(anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0], "body": [1.0, 0.0]})
    rule = SemanticRule(embedder, corpus)
    target = _skill(body="body")
    assert rule.check(target) == rule.check(target)


def test_non_skill_target_yields_nothing():
    corpus = _corpus(anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0]})
    rule = SemanticRule(embedder, corpus)
    target = Target(kind=TargetKind.MCP_SERVER, name="srv", location=SourceLocation(path="mcp.json"))
    assert rule.check(target) == []


def test_empty_body_yields_nothing():
    corpus = _corpus(anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0]})
    rule = SemanticRule(embedder, corpus)
    assert rule.check(_skill(body="   \n")) == []


# --- registry gating --------------------------------------------------------


def test_default_registry_excludes_semantic_rule_and_constructs_no_embedder():
    constructed: list[bool] = []

    class RecordingEmbedder:
        def __init__(self):
            constructed.append(True)

        def embed(self, text):
            return [0.0]

    registry = build_default_registry()
    assert "SKL-semantic-malicious" not in registry
    assert constructed == []  # no embedder was ever constructed


def test_registry_includes_semantic_rule_when_embedder_configured():
    corpus = _corpus(anchors=("steal all data",))
    embedder = _DictEmbedder({"steal all data": [1.0, 0.0]})
    registry = build_default_registry(embedder=embedder, corpus=corpus)
    assert "SKL-semantic-malicious" in registry
