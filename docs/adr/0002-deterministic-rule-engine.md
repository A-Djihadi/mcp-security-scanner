# ADR-0002: Deterministic rule engine with a declarative rule definition

**Status:** accepted

## Context

The MVP must run **deterministic static rules only** (embeddings deferred — see
ADR-0005). We need a rule model that is easy to add to, easy to test in
isolation, and does not grow a framework.

## Decision

Rules are plain classes implementing a minimal interface:

```python
class Rule(Protocol):
    id: str
    level: str            # "error" | "warning" | "note"
    short_description: str
    def check(self, target: Target) -> list[Finding]: ...
```

A `RuleRegistry` holds the enabled set; a `RuleEngine.run(targets)` applies every
enabled rule to every target, dedups identical findings, and sorts deterministically
(by file, line, rule ID). Rules are **pure** (no I/O, no shared state), which is
what makes them unit-testable through the `check(target)` seam and makes the scan
byte-for-byte reproducible.

## Considered options

- **A DSL / config-driven rule engine** (rules as YAML/JSON with regex bodies) —
  rejecting for MVP: regexes in a config file are harder to test, harder to
  debug, and give weaker IDE support than Python. Reintroduce as a phase-2
  add-on if the rule count justifies it.
- **A single monolithic `analyze()` function** — rejecting: kills per-rule
  testability and makes the rule taxonomy unmaintainable.
- **Bandit-style plugin system** — rejecting: overkill for a greenfield tool
  with a handful of rules; the `Rule` protocol is the entire plugin surface.

## Consequences

- Adding a rule = one class + one fixture + tests; no framework changes.
- The `Rule` protocol is the single external seam rules cross, so tests never
  touch the engine's internals.
- Determinism is a property of the engine's ordering contract, and is itself
  under test.
