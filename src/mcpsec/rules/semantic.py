"""Semantic malicious-intent rule: cosine similarity against a curated corpus.

Pure, deterministic and offline (ADR-0008). The rule is constructed with an
``Embedder`` and a versioned ``SemanticCorpus``; it embeds each skill's body and
compares it to the malicious anchors' precomputed embeddings, emitting
``SKL-semantic-malicious`` (warning) when the similarity reaches a fixed,
injectable threshold. No model is shipped here — the embedder is supplied by
the caller.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from ..model import Embedder, Finding, Target, TargetKind

DEFAULT_THRESHOLD = 0.85


@dataclass(frozen=True)
class CorpusAnchor:
    """One curated reference text in the semantic corpus."""

    id: str
    text: str
    malicious: bool


@dataclass(frozen=True)
class SemanticCorpus:
    """A versioned collection of curated reference anchors."""

    version: str
    anchors: tuple[CorpusAnchor, ...]


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two equal-length vectors (0.0 if either is zero)."""
    if len(a) != len(b):
        raise ValueError("vectors must have equal length")
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


class SemanticRule:
    id = "SKL-semantic-malicious"
    level = "warning"
    short_description = "Skill prose is semantically similar to a known-malicious reference."
    online = False

    def __init__(
        self,
        embedder: Embedder,
        corpus: SemanticCorpus,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self._embedder = embedder
        self._corpus = corpus
        self._threshold = threshold
        self._model_name = getattr(embedder, "name", None)
        self._model_version = getattr(embedder, "version", None)
        self._anchors = tuple(
            (anchor, tuple(embedder.embed(anchor.text)))
            for anchor in corpus.anchors
            if anchor.malicious
        )

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.SKILL:
            return []
        body = target.payload.get("body") or ""
        if not body.strip():
            return []

        vector = self._embedder.embed(body)
        best_anchor: CorpusAnchor | None = None
        best_similarity = -1.0
        for anchor, anchor_vector in self._anchors:
            similarity = cosine_similarity(vector, anchor_vector)
            if similarity > best_similarity:
                best_similarity = similarity
                best_anchor = anchor

        if best_anchor is None or best_similarity < self._threshold:
            return []

        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'skill "{target.name}" is semantically similar to malicious '
                    f'reference "{best_anchor.id}" (corpus v{self._corpus.version})'
                ),
                location=target.location,
                properties=self._properties(best_anchor, best_similarity),
            )
        ]

    def _properties(self, anchor: CorpusAnchor, similarity: float) -> dict:
        properties = {
            "corpus_version": self._corpus.version,
            "matched_anchor": anchor.id,
            "similarity": round(similarity, 6),
            "threshold": self._threshold,
        }
        if self._model_name:
            properties["model"] = self._model_name
        if self._model_version:
            properties["model_version"] = self._model_version
        return properties
