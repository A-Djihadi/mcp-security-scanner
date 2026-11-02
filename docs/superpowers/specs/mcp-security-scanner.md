# Spec — mcp-security-scanner

Static security scanner for MCP servers and AI agent skills. Detects excessive
permissions (unrestricted shell, unsanitized SQL), risky dependencies, and
malicious patterns. Emits SARIF v2.1.0 for CI integration.

## Problem Statement

MCP servers and agent "skills" (Hermes `SKILL.md`, Claude/agent skills) are
increasingly the vector through which AI agents gain shell, network, filesystem,
and database access. Config files (`mcp.json`, `claude_desktop_config.json`,
`package.json#mcpServers`) and `SKILL.md` files declare powerful capabilities with
little or no review. A developer or reviewer has no single, deterministic,
CI-friendly tool to answer: *"does this config / skill grant more power than it
should?"* and *"do these dependencies pin their versions?"*.

## Solution

A command-line static scanner, `mcpsec`, that:

1. Discovers MCP config files and skill files under a target directory.
2. Parses each format into a normalized in-memory model (see
   `docs/domain-model.md`).
3. Runs a set of **deterministic static rules** (no network, no paid API, no ML)
   over the model.
4. Emits every finding as **SARIF v2.1.0** (default) or human-readable text.
5. Exits with a machine-friendly code so CI can gate on it.

## Scope

### MVP (phase 1)

| Area | In scope |
|------|----------|
| Inputs | `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `package.json` (`mcpServers` field + dependency manifests), `requirements.txt`, `pyproject.toml`, `SKILL.md` (incl. Hermes `profiles/*/skills/*/SKILL.md` layout). |
| Detection | Deterministic static rules only: permission-excess, risky-dependency (version pinning), malicious-pattern. |
| Output | SARIF v2.1.0 (`--format sarif`) and human text (`--format text`). |
| Dependencies | No paid API. No network access at scan time. |
| CI | Exit codes suitable for a blocking gate; a documented GitHub Actions usage example (no CI file shipped in phase 1). |

### Explicitly deferred (phase 2+)

| Area | Phase | Reason |
|------|-------|--------|
| Semantic / embedding-based pattern matching (malicious-intent detection beyond syntactic signatures) | 2 | Decided: DIFFERRED. See ADR-0005. |
| Registry-backed checks: "outdated" / "known-vulnerable" / "unknown (typosquat)" dependencies | 2 | Requires network + registry/OSV data; deterministic-only in MVP. See ADR-0006. |
| Remote MCP servers (HTTP/SSE/WS transport): header/auth hygiene, live reachability | 2 | Config shape varies by client; "to verify" per client. |
| `smithery.yaml` | 2 | Format not yet verified (see Open Questions). |
| Taint/flow analysis across a server's source tree | 2+ | MVP scans config/skill text, not arbitrary codebases. |
| Auto-fix / `--fix` | 3 | |

## Supported inputs

Each format is mapped to a normalized target by a dedicated parser. Details and
data-flow in `docs/domain-model.md`.

| Format | Typical location | Key fields read | Certainty |
|--------|------------------|-----------------|-----------|
| `mcp.json` (project root / `.cursor/mcp.json`-style) | repo root, `.cursor/mcp.json` | top-level `mcpServers` map: `command`, `args`, `env`, `cwd`, `type`, `url`, `headers` | Confirmed for Claude Code `.mcp.json` and Cursor; top-level key and remote-entry shape vary per client — parsers must tolerate `servers` vs `mcpServers`. |
| `claude_desktop_config.json` | `%APPDATA%\Claude\`, `~/.config/Claude/`, `~/Library/Application Support/Claude/` | top-level `mcpServers`: `command`, `args`, `env` (stdio transport only) | Confirmed. |
| `package.json` | repo root | `mcpServers` field (same shape as MCP config) **and** `dependencies` / `devDependencies` | `mcpServers` field existence: "to verify" (accepted per task; exact shape to confirm against a real example during T4). |
| `requirements.txt` | repo root | pinned vs unpinned requirements | Confirmed. |
| `pyproject.toml` | repo root | `[project] dependencies`, `[project.optional-dependencies]`, `[tool.poetry.dependencies]` | Confirmed (PEP 621 + Poetry section). |
| `SKILL.md` | Hermes `profiles/*/skills/*/SKILL.md`; any `SKILL.md` | YAML frontmatter + markdown body | Confirmed for Hermes layout; Claude/agent skill frontmatter keys vary — parser must tolerate unknown keys. |

### Position tracking (locations)

SARIF findings must point at the offending line/column. YAML (PyYAML) and
markdown (line-indexed) give positions directly. **JSON** does not: Python's
`json` module discards positions. The parser records, for each `mcpServers` key,
the byte offset of the key token while scanning the raw text, then maps
offset → line/column via a precomputed line-offset index (deterministic,
dependency-free). Repeated keys resolve to the first occurrence; this limitation
is documented and tested.

## Rule taxonomy

Rule IDs are stable strings, prefixed by category. Severity maps to the SARIF
`level` (`error` | `warning` | `note`). All MVP rules are **deterministic**:
same input ⇒ same findings, no network, no randomness.

### Permissions (MCP server config + skill bodies)

| Rule ID | Level | Trigger |
|---------|-------|---------|
| `MCP-shell-unrestricted` | error | Server `command` is a shell interpreter (`sh`, `bash`, `zsh`, `cmd.exe`, `powershell`, `pwsh`) or `args` executes an arbitrary, unquoted command (e.g. `sh -c "<user-controlled>"`). |
| `MCP-allow-all` | error | `args` contain an `--allow-all` / `--allow-everything` / `-A` flag, or Deno/Node permission flags that disable a whole class (`--allow-run`, `--allow-ffi`) with no restriction. |
| `MCP-broad-network` | error | `--allow-net` with no host restriction, or a remote `url`/`type` that permits arbitrary egress (heuristic: no explicit host allowlist in args). |
| `MCP-broad-filesystem` | warning | `--allow-read` / `--allow-write` / `--allow-read-write` with root-level path (`/`, `~`, `C:\`, `C:/`) or no path, or a filesystem server rooted at `/`. |

### Malicious / dangerous patterns (skill bodies + command args)

| Rule ID | Level | Trigger |
|---------|-------|---------|
| `SKL-remote-code-exec` | error | Pipe-to-shell of remote content: `curl … \| sh`, `wget … \| bash`, `eval(fetch(…))`, `powershell -Command "Invoke-WebRequest … \| Invoke-Expression"`. |
| `SKL-obfuscated-command` | warning | Shell command containing a `base64 -d`/`base64 --decode` payload or a long high-entropy `eval`/`exec` argument. |
| `SKL-sql-concatenation` | error | SQL built by string concatenation/interpolation: `f"SELECT … {var}"`, `"SELECT …" + var`, `.format(...)` into a query, unparameterized `execute(...)`. |
| `SKL-shell-execution` | warning | Skill body invokes a shell with user/skill input passed unsanitized (f-string into `subprocess`/`os.system`/backticks). |

### Dependencies

| Rule ID | Level | Trigger |
|---------|-------|---------|
| `DEP-unpinned` | warning | A direct dependency whose version spec is unpinned or a wildcard: empty/`*`/`latest`, `requirements.txt` without `==`, npm `^`/`~` ranges, PEP 508 without a `==`/`===` pin. |

> Registry-backed rules (`DEP-outdated`, `DEP-unknown`/typosquat,
> `DEP-known-vulnerability`) are **phase 2** — see ADR-0006.

## Output format

### SARIF v2.1.0

Single `sarifLog` object; one `run`. Conforms to the official schema
(`https://json.schemastore.org/sarif-2.1.0.json`). See ADR-0004 for the exact
shape, including `tool.driver.rules`, `results[].ruleIndex`, `level`,
`message.text`, `locations[].physicalLocation.artifactLocation.uri`,
`region.startLine/startColumn`, and `partialFingerprints`.

### Text

One line per finding:

```
[error] MCP-shell-unrestricted — mcp.json:12:5 — server "admin" runs an unrestricted shell
```

## CLI usage

```
# Scan a directory, write SARIF, gate on error-level findings
mcpsec scan . --output results.sarif

# Human-readable, all severities, no SARIF
mcpsec scan . --format text

# Only error-level; only specific rules
mcpsec scan . --severity error --rules MCP-shell-unrestricted,DEP-unpinned

# Exclude a rule (e.g. too noisy for this repo)
mcpsec scan . --exclude-rule SKL-shell-execution
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no findings at or above `--fail-on` threshold (default `error`). |
| 1 | Scan completed; one or more findings at or above the threshold. |
| 2 | Internal error (bad args, unreadable path, unexpected exception). |

## User stories

1. As a security reviewer, I want to scan a repo's `mcp.json` and get a SARIF
   report, so that I can review every excessive-permission grant in one place.
2. As a CI pipeline, I want `mcpsec` to exit non-zero when an error-level
   finding exists, so that a risky MCP config blocks the build.
3. As a developer, I want findings to point at the exact file/line/column, so
   that I can jump straight to the offending grant.
4. As a developer, I want a human-readable text mode, so that I can read findings
   in a terminal without a SARIF viewer.
5. As a maintainer, I want to enable/disable rules per repo, so that a known
   acceptable pattern does not fail CI forever.
6. As a developer, I want my `claude_desktop_config.json` scanned, so that my
   local MCP servers are audited too.
7. As a developer, I want my Hermes `profiles/*/skills/*/SKILL.md` files scanned,
   so that skills I install are vetted before use.
8. As a security reviewer, I want a skill that runs `curl … | sh` flagged as
   remote-code-exec, so that drive-by installs are caught.
9. As a security reviewer, I want unparameterized SQL flagged, so that SQL
   injection via a skill or MCP tool is caught statically.
10. As a maintainer, I want unpinned dependencies flagged, so that supply-chain
    risk from floating versions is visible.
11. As a developer, I want the scanner to be deterministic and offline, so that
    CI runs are reproducible and cost nothing.
12. As a future contributor, I want a documented rule taxonomy and ADRs, so that
    adding a rule does not require reverse-engineering the design.

## Implementation decisions

See the ADRs, which are the source of truth for the choices below:

- **Language & packaging**: Python 3.13, `uv`, single import package `mcpsec`,
  only runtime dependency is `PyYAML`. ADR-0001.
- **Rule engine**: deterministic rules over a normalized target model, with a
  declarative rule definition and a registry. ADR-0002.
- **Parsing**: one parser per format, all emitting a shared normalized target
  model with source locations. ADR-0003.
- **Output**: SARIF v2.1.0 writer as a separate module. ADR-0004.
- **Semantic patterns deferred**. ADR-0005.
- **Dependency policy**: pinning checks are deterministic/offline; registry
  checks are phase 2. ADR-0006.

## Testing decisions

- **TDD**: every ticket writes its failing tests first (RED), then implements to
  GREEN, then refactors. `pytest` is the runner.
- **Test only external behaviour**: tests drive the public seams (parsers'
  `parse(path) -> list[Target]`, `RuleEngine`, `SARIFWriter`), never private
  helpers. See `docs/domain-model.md` for the seam surface.
- **Fixtures** are checked-in sample files under `tests/fixtures/`, one per
  format and per rule trigger, kept tiny and hand-written (no generated goldens
  that hide intent).
- **SARIF validation**: a test asserts structural invariants (required fields,
  `version == "2.1.0"`, every `ruleIndex` resolves into `tool.driver.rules`,
  `level` ∈ {error, warning, note}). Optional offline schema validation uses a
  vendored copy of the official schema; if vendoring is rejected, structural
  assertions stand alone (see ADR-0004).
- **Determinism test**: scanning the same fixture twice yields byte-identical
  SARIF (stable ordering: findings sorted by file, then line, then rule ID).

## Out of scope

- Executing or installing any MCP server or skill (pure static analysis).
- Scanning arbitrary application source code for SQL/taint (MVP covers config +
  skill text only).
- Remote-server reachability, live header inspection, OAuth config review.
- Reporting against a live vulnerability feed.
- Generating or modifying MCP/skill files.

## Open questions (reported to CHIEF)

1. `package.json` `mcpServers` field: exact schema to confirm against a real
   example before T4 (accepted here as "same shape as `mcp.json`" — to verify).
2. `smithery.yaml` schema: deferred to phase 2; format not yet verified against
   Smithery docs.
3. Severity defaults: is `DEP-unpinned` a `warning` or a `note`? Default here is
   `warning`; adjustable via rule config.
4. Should the MVP ship a GitHub Actions workflow file, or only document the
   snippet? Decided: document only, ship workflow in a later ticket.
5. Package distribution name for PyPI (if ever published): `mcp-security-scanner`
   assumed; rename is cheap before first release.
