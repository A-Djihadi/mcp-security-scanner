# ADR-0009: Taint/flow analysis — Python-first via stdlib `ast`, no new dependency

**Status:** accepted

## Context

Issue #7 wants taint/flow analysis across an MCP server's source tree: trace
unsanitized input (MCP tool request parameters) into dangerous sinks (shell
execution, SQL, `eval`). Phase 1 explicitly scoped the scanner to config + skill
text; scanning arbitrary codebases is the phase-2 extension. The core design
question is the analysis mechanism — real AST/dataflow tooling vs. regex — and
which languages are in scope, given the "no new third-party dependency without
an ADR" rule and the deterministic-offline guarantee.

## Decision

**Python-first, using the standard library `ast` module — zero new dependency.**

- **Mechanism:** a conservative, deterministic taint analysis built on `ast`
  (stdlib, no dependency): identify **sources** (the parameters of MCP tool
  handlers, i.e. values derived from `request.params` / tool-call arguments),
  propagate taint through **propagators** (assignment, string formatting/
  concatenation/`join`, dict/list access, function returns), and report when a
  tainted value reaches a **sink** (shell: `os.system`/`subprocess.*`/`Popen`;
  code eval: `eval`/`exec`/`compile`; SQL: `execute`/`executemany`/`raw`).
  Regex is used only for tokenization/identifier matching *inside* the AST walk,
  not as the analysis itself (consistent with ADR-0002's rejection of a regex
  rule DSL).
- **Scope:** **Python source trees only** in phase 2. Python is the most common
  MCP-server implementation language, is the scanner's own language, and needs
  no new dependency. JavaScript/TypeScript are **deferred** to a later phase
  pending an owner decision to add `tree-sitter` + grammars (a native dependency
  requiring its own ADR) — see T23.
- **Rule IDs:** `FLOW-*` — `FLOW-shell-injection` (error), `FLOW-sql-injection`
  (error), `FLOW-code-eval` (warning). Deterministic and offline: the analysis
  is a pure function of the source text.
- **False positives:** the analysis is conservative by design — it reports
  *possible* taint (over-approximation) and never claims sanitization it cannot
  prove. Sanitizer recognition (e.g. a call through a known escaping function)
  is a documented, versioned list; unrecognized sanitizers are treated as
  absent (favor recall over precision; document this in the rule description).

## Considered options

- **Regex-based flow matching** — rejected as the mechanism: cannot track taint
  across assignments/function boundaries, high false-positive/negative rate;
  it is exactly the fragility ADR-0002 rejected for the rule engine.
- **A third-party SAST tool (Bandit, Semgrep rules, CodeQL)** — rejected for
  phase 2: adds a heavy dependency (or an external engine) and breaks the
  single-process, PyYAML-only, deterministic guarantee; re-evaluate if the
  in-house `ast` analyzer proves insufficient.
- **`tree-sitter` for Python too** — rejected: stdlib `ast` is sufficient and
  free; `tree-sitter` buys nothing for Python.
- **Multi-language in phase 2** — rejected: each language is a real grammar +
  AST + taint-rules effort; scoping to Python keeps T22 a bounded, shippable
  increment. JS/TS (T23) is the explicit next increment.

## Consequences

- `FLOW-*` rules are pure, deterministic, offline, and unit-testable against
  checked-in Python fixtures — no new dependency, base install unchanged.
- Taint analysis is a new rule *category*, reusing the `Rule.check(target)` seam;
  the `Target` for a source tree is a new `kind` (see `domain-model.md` note) or
  a dedicated analyzer that emits findings directly — the parser/engine seams
  are unchanged.
- Python-only scope is a documented limitation; JS/TS support is gated on an
  owner decision (new native dependency) and lands as T23.
- Conservative over-approximation means some false positives on real code; that
  is an accepted trade-off documented in the rule descriptions and configurable
  via `--exclude-rule`.
