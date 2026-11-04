# Domain Model — mcp-security-scanner

Canonical vocabulary: `GLOSSARY.md`. This document describes the entities, their
relationships, and the data flow. It is the reference for what the parsers, rule
engine, and SARIF writer operate on.

## Entities

```
Scanner ──dispatches──▶ Parser ──emits──▶ Target ──consumed by──▶ RuleEngine ──emits──▶ Finding ──consumed by──▶ SARIFWriter ──▶ .sarif
   │                                                                    ▲
   └── CLI ── exit code ────────────────────────────────────────────────┘
```

### Target (normalized model)

The unit every parser produces and every rule consumes. Discriminated by `kind`.

| Field | Type | Notes |
|-------|------|-------|
| `kind` | enum | `mcp_server` \| `skill` \| `dependency` \| `python_source` |
| `location` | `SourceLocation` | file + spans (see below). |
| `name` | str | server name / skill name / package name. |
| `payload` | dict | kind-specific, see variants. |

**`McpServer` (kind=mcp_server)** — `payload`: `command` (str|null), `args`
(list[str]), `env` (dict), `cwd` (str|null), `transport` (`stdio`|`remote`),
`url` (str|null). Every field carries its own `SourceLocation` so a rule can
point at exactly the offending `args` element or `command` value.

**`Skill` (kind=skill)** — `payload`: `frontmatter` (dict, YAML), `body` (str,
markdown, line-indexed), `body_lines` (list[str] for line-accurate matches).

**`Dependency` (kind=dependency)** — `payload`: `version_spec` (str), `manifest`
(str path), `pinned` (bool, computed by the parser), `source` (str: the exact
declaration line).

**`PythonSource` (kind=python_source)** — `payload`: `source` (str, the raw file
text). Produced by `PythonSourceParser` for each `*.py` file; consumed by the
`FLOW-*` taint rules (T22, ADR-0009), which run a stdlib-`ast` taint analysis
over the source. `name` is the normalized file path; `location` is the file
itself (line 1).

### SourceLocation

| Field | Type | Notes |
|-------|------|-------|
| `path` | str | path relative to the scan root (URI-safe). |
| `start_line` / `start_column` | int|null | 1-based. |
| `end_line` / `end_column` | int|null | optional. |
| `snippet` | str|null | the offending text (used for fingerprints). |

### Rule

Interface (see ADR-0002): `id`, `level`, `short_description`, and
`check(target: Target) -> list[Finding]`. A rule is **pure**: no I/O, no state,
no randomness. The `RuleEngine` passes each target to every enabled rule.

### Finding

The canonical result object (independent of SARIF).

| Field | Type | Notes |
|-------|------|-------|
| `rule_id` | str | stable rule ID. |
| `level` | str | `error` \| `warning` \| `note`. |
| `message` | str | human-readable, no formatting assumptions. |
| `location` | `SourceLocation` | primary location. |
| `fingerprint` | str | deterministic hash of `(rule_id, path, start_line, snippet)` — for CI baselines. |

### RuleEngine

Owns the rule registry (enabled/disabled set, severity threshold) and the
application loop. Interface: `run(targets: Iterable[Target]) -> list[Finding]`.
Small surface, deep implementation (ordering, dedup, filtering).

### Parser (adapter per format)

Interface: `parse(path) -> list[Target]`. One adapter per format:
`McpJsonParser`, `ClaudeDesktopConfigParser`, `PackageJsonParser`,
`RequirementsParser`, `PyprojectParser`, `SkillMarkdownParser`. A parser that
does not recognize a file returns an empty list (discovery decides which parser
to call). JSON parsers record key byte-offsets to build `SourceLocation`s (see
spec — Position tracking).

### SARIFWriter

Interface: `write(findings: list[Finding], rules: RuleRegistry, out: Path) -> None`.
Maps `Finding` + rule metadata to a single-run SARIF 2.1.0 document. Purely a
projection; holds no domain logic.

### CLI / Scanner

Entry point. Responsibilities: parse args, discover files, dispatch to parsers,
invoke `RuleEngine`, invoke `SARIFWriter` (or text formatter), compute exit code.

## Data flow

```mermaid
flowchart LR
    subgraph Inputs
        F[files on disk]
    end
    subgraph Parse
        D[discovery] --> P[parsers]
        P --> T[Target[]]
    end
    subgraph Analyze
        T --> E[RuleEngine]
        E --> G[Finding[]]
    end
    subgraph Report
        G --> W[SARIFWriter]
        W --> O[results.sarif]
        G --> X[TextFormatter]
        X --> C[stdout]
    end
    E -->|count at/above threshold| XC[exit code]
```

1. **Discovery** walks the target path, matching known filenames
   (`mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `package.json`,
   `requirements.txt`, `pyproject.toml`, `SKILL.md`, Hermes `profiles/*/skills/*/SKILL.md`).
2. **Parsers** each emit `Target[]` (empty list = "not for me").
3. **RuleEngine** applies enabled rules, dedups, sorts deterministically.
4. **SARIFWriter** / **TextFormatter** project findings to output.
5. **Exit code** derived from findings vs the `--fail-on` threshold.

## Seams (test surface)

Tests cross these interfaces only:

- `Parser.parse(path) -> list[Target]` — golden-target tests per fixture.
- `Rule.check(target) -> list[Finding]` — one rule × one fixture.
- `RuleEngine.run(targets) -> list[Finding]` — ordering/filter/dedup.
- `SARIFWriter.write(...)` — structural + determinism assertions.

No test reaches past these into private helpers.
