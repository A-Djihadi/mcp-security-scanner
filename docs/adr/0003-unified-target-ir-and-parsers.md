# ADR-0003: One parser per format, unified Target model with source locations

**Status:** accepted

## Context

The scanner reads multiple file formats (JSON MCP configs, YAML/JSON dependency
manifests, markdown skills) whose shapes overlap but whose parsing and
position-tracking differ. We need a parse layer that isolates format quirks from
the rule engine.

## Decision

Each format gets one **parser adapter** implementing `parse(path) -> list[Target]`;
a parser returns `[]` for a file it does not own. All parsers emit the **unified
`Target` model** (`McpServer`, `Skill`, `Dependency`) with per-field
`SourceLocation`s. YAML uses PyYAML's `Mark`; markdown uses a line index; **JSON
parsers record key byte-offsets** while scanning raw text, then map
offset → line/column via a precomputed line-offset index — because `json.load`
discards positions.

## Considered options

- **One generic JSON/YAML tree-walker** that treats every file as an untyped
  dict — rejecting: loses the field-level location granularity rules need, and
  blurs format-specific semantics (e.g. `args` is an ordered list, `env` is a
  map) into one undifferentiated mass.
- **A positional JSON library dependency** — rejecting for now: a small
  byte-offset scanner is ~50 lines, deterministic, and keeps the dependency set
  minimal (ADR-0001). Revisit if repeated-key location accuracy becomes a hard
  requirement.
- **Emit raw dicts and let rules re-locate** — rejecting: pushes location logic
  into every rule, violating locality.

## Consequences

- Rules consume only `Target`s, so a new input format is one new parser, zero
  rule changes.
- Location accuracy for repeated JSON keys is best-effort (first occurrence);
  documented and covered by a test.
- The parser interface (`parse(path) -> list[Target]`) is the test seam.
