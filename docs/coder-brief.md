# Coder Brief — mcp-security-scanner

Read this before writing any code. It is the contract between the design
(`docs/superpowers/specs/`, `docs/adr/`, `docs/domain-model.md`, `docs/tickets.md`)
and the implementation. When the design and this brief conflict, the design wins
— flag the conflict rather than silently picking one.

## What you are building

A static security scanner, `mcpsec`, that scans MCP server configs and agent
skills for excessive permissions, risky dependencies, and malicious patterns,
and emits SARIF v2.1.0 for CI.

## Order of implementation

Work tickets in order (T1 → T10), but **you may parallelize** T3/T4/T5/T6 once
T2 lands, and T7/T8/T9 once their parsers + T6 land. Always finish a ticket's
acceptance criteria (all tests green) before starting the next. `docs/tickets.md`
lists the blocking edges.

1. **T1** scaffolding → 2. **T2** domain + SARIF writer → 3. **T3–T6** parsers +
engine → 4. **T7–T9** rules → 5. **T10** CLI + E2E + docs.

## Stack (exact)

- **Language/runtime:** Python 3.13 — use `python3` (the 3.13 interpreter). Do
  NOT use `python` (resolves to 3.14) or bare `pip` (points at 3.15).
- **Package manager:** `uv` (already installed). `uv init`, `uv add PyYAML`,
  `uv add --dev pytest`, `uv run …`.
- **Runtime dependency:** `PyYAML` only. Everything else from the standard
  library (`json`, `argparse`, `pathlib`, `re`, `dataclasses`, `hashlib`).
- **Tests:** `pytest`. Run with `uv run pytest`.
- **Import package:** `mcpsec`. Distribution name `mcp-security-scanner`.

## Layout

```
mcp-security-scanner/
├── pyproject.toml
├── README.md
├── GLOSSARY.md
├── docs/
│   ├── adr/            # design decisions (read, do not edit without a new ADR)
│   ├── domain-model.md
│   ├── tickets.md
│   └── coder-brief.md
├── src/mcpsec/
│   ├── __init__.py
│   ├── cli.py          # argparse, scan command, exit codes
│   ├── discovery.py    # file discovery
│   ├── model.py        # Target, McpServer, Skill, Dependency, SourceLocation, Finding, Rule
│   ├── parsers/        # one module per format
│   ├── engine.py       # RuleEngine + RuleRegistry
│   ├── rules/          # one module per rule (or per rule group)
│   ├── sarif.py        # SARIFWriter
│   └── text.py         # text formatter
└── tests/
    ├── fixtures/       # hand-written sample files, one per format + trigger
    └── test_*.py
```

## Conventions

- **TDD only.** Write the failing test first, watch it fail, make it pass,
  refactor. Never implement before the test exists.
- **Test external behaviour, not internals.** Tests drive only the seams in
  `docs/domain-model.md`: `Parser.parse(path)`, `Rule.check(target)`,
  `RuleEngine.run(targets)`, `SARIFWriter.write(...)`. No test reaches past
  these interfaces.
- **Deep modules.** Small public interfaces, logic hidden inside. The `Rule`
  protocol, `Parser.parse`, `RuleEngine.run`, and `SARIFWriter.write` are the
  whole external surface; everything else is private.
- **Pure rules.** A rule does no I/O, holds no mutable state, and returns
  `list[Finding]`. This is what makes scans deterministic and rules unit-testable.
- **Determinism.** Findings are always sorted (path, line, rule id) and deduped;
  two runs over the same input are byte-identical. This is under test (T2, T10).
- **Locations.** YAML → PyYAML `Mark`; markdown → line index; JSON → key
  byte-offset mapped through a precomputed line-offset index (see ADR-0003).
- **No network, no paid API, no randomness** at scan time. Default scan is fully
  offline.
- **Messages & comments in English** (the user's standard; task summary in
  French, but code and commits are English).

## Testing commands

```bash
uv run pytest                      # full suite
uv run pytest tests/test_sarif.py -q   # one module
uv run mcpsec scan tests/fixtures/e2e --output /tmp/out.sarif   # manual smoke
```

(On this Windows host, prefer forward-slash native paths for anything a native
tool reads; `$TMPDIR` points at Hermes' scratch dir.)

## Acceptance bar

A ticket is done when **all** its acceptance criteria in `docs/tickets.md` pass,
`uv run pytest` is green across the whole suite, and no pre-existing test was
weakened. Do not mark done on a partial subset.

## Guardrails (do not)

- Do not edit `main`. Work on a feature branch per ticket.
- Do not add third-party runtime deps beyond `PyYAML` without a new ADR.
- Do not ship a CI workflow file in phase 1 — document the snippet in `README.md`
  only (see spec — Open questions #4).
- Do not invent format facts: if a format's real shape is uncertain (see spec —
  "Certainty" column), treat it as "to verify" and add a fixture that pins your
  assumption, rather than guessing silently.
