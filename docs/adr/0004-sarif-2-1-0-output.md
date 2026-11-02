# ADR-0004: SARIF v2.1.0 output as a separate writer module

**Status:** accepted

## Context

SARIF v2.1.0 is fixed by the brief. The writer is a projection of `Finding`s and
rule metadata; it must be schema-valid and CI-consumable, but must not leak SARIF
concepts into the domain model.

## Decision

A dedicated `SARIFWriter.write(findings, rules, out)` emits one `sarifLog` with a
single `run`:

- `version: "2.1.0"`, `$schema: https://json.schemastore.org/sarif-2.1.0.json`.
- `runs[0].tool.driver`: `name: "mcpsec"`, `version`, and `rules[]` — one entry
  per rule in the registry, with `id` and `shortDescription.text`.
- `runs[0].results[]`: one per finding — `ruleId`, `ruleIndex` (into `rules[]`),
  `level`, `message.text`, `locations[0].physicalLocation.artifactLocation.uri`
  (relative to scan root), `region.startLine`/`startColumn`, and
  `partialFingerprints` with a `primary` hash.

The domain `Finding` stays SARIF-agnostic; only the writer knows the schema.

## Considered options

- **Emit `level` only on results, not rules** — partially rejected: set
  `level` on the result (explicit) *and* `defaultConfiguration.level` on the
  rule, so viewers that only read one of them still resolve severity correctly.
- **One SARIF run per input file** — rejecting: a single run per scan keeps
  `ruleIndex` resolution simple and matches how CI tooling consumes results.
- **Vendor the full OASIS schema for offline validation** — deferred: tests
  assert the structural invariants (required fields, version, ruleIndex
  resolvable, level enum). Vendoring is an optional follow-up if a
  schema-validator dependency is ever acceptable.

## Consequences

- Severity is unambiguous even for consumers that ignore `ruleIndex`.
- The writer is independently unit-tested by constructing `Finding`s directly,
  with no need to run the engine.
- Changing output format later (e.g. adding a second run) is localized to the
  writer.
