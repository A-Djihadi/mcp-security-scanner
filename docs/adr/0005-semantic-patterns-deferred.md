# ADR-0005: Semantic / embedding patterns deferred to phase 2

**Status:** superseded by ADR-0008 (the phase-2 approach is now decided; this
ADR remains as the record of the MVP deferral).

## Context

The brief defers embeddings/semantic pattern matching and restricts the MVP to
deterministic static rules. This ADR records *why* and what the later seam looks
like, so phase 2 does not require re-architecting.

## Decision

The MVP ships **deterministic rules only** (ADR-0002). Semantic/embedding-based
detection (e.g. "this skill's prose intent is to exfiltrate data despite benign
syntax") is out of scope. The `Rule` protocol is deliberately the future seam: a
phase-2 `SemanticRule` can implement the same `check(target) -> list[Finding]`
interface, consuming a model/lookup injected at construction, without touching
the engine or the parsers.

## Considered options

- **Fold embeddings into the MVP** — rejected by the brief and by cost: it
  introduces a model dependency, non-determinism, and a (possibly paid) runtime,
  all forbidden in MVP and CI.
- **Design a separate "semantic engine" now** — rejecting: premature; the shared
  `Rule` interface is already a sufficient seam, and designing it twice risks
  speculation.

## Consequences

- MVP remains deterministic, offline, dependency-light, and CI-safe.
- The `Rule` interface is the only coupling phase 2 must respect.
- No paid API, no model, and no network are introduced by this deferral.
