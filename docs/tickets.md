# Tickets — mcp-security-scanner

Ordered, test-first tickets. Each ticket is a vertical, demoable increment. Read
`docs/coder-brief.md` for conventions and stack before implementing. A ticket's
acceptance criteria are written as tests to write FIRST (RED), then satisfy.

Complexity scale: **S** (≤1 day), **M** (1–2 days), **L** (2–3 days).

Dependency graph:

```
T1 ─┬─▶ T2 ─┬─▶ T3 ─┐
   │        ├─▶ T4 ─┤
   │        ├─▶ T5 ─┤
   │        └─▶ T6 ─┼─▶ T7 ─┐
   │                 ├─▶ T8 ─┼─▶ T10
   │                 └─▶ T9 ─┘
   └─(all parser tickets also need T2 for Target model)
```

---

## T1 — Project scaffolding & CLI skeleton — S

**Blocked by:** none (can start immediately).

**What to build:** a `uv`-managed package `mcpsec` with a working `scan` command
that walks a directory and exits 0 with no findings. Establishes the layout,
test runner, and deterministic foundation every later ticket builds on.

**Acceptance criteria (tests first):**
- [ ] `uv run mcpsec scan .` on an empty dir exits 0.
- [ ] `uv run mcpsec scan .` on a dir with no recognized files produces an empty
      `{"version":"2.1.0","runs":[{"results":[]}]}` SARIF (structural skeleton only).
- [ ] `mcpsec --help` prints `scan` as a subcommand.
- [ ] `uv run pytest` passes (a trivial placeholder test proves the harness).
- [ ] `pyproject.toml` declares `requires-python = ">=3.13"` and `pytest` as a
      dev dependency; `PyYAML` as the sole runtime dependency.

---

## T2 — Domain model & SARIF v2.1.0 writer — M

**Blocked by:** T1.

**What to build:** the core domain objects (`Target`/`McpServer`/`Skill`/
`Dependency`, `SourceLocation`, `Finding`, `Rule` protocol) and `SARIFWriter`,
so a list of `Finding`s becomes a schema-valid SARIF document.

**Acceptance criteria (tests first):**
- [ ] `SARIFWriter.write` emits `version == "2.1.0"` and a single `run`.
- [ ] Every result carries `ruleId`, `ruleIndex` resolving into
      `tool.driver.rules`, `level` ∈ {error, warning, note}, `message.text`, and
      `locations[0].physicalLocation.artifactLocation.uri`.
- [ ] `region.startLine`/`startColumn` are present when the `Finding` has them.
- [ ] Output ordering is deterministic (findings sorted by path, line, rule id).
- [ ] `partialFingerprints.primary` is a stable hash of (rule, path, line, snippet):
      two identical findings hash equal; changing any component changes the hash.
- [ ] Two consecutive `write` calls produce byte-identical files.

---

## T3 — MCP config parsers (`mcp.json`, `.mcp.json`, `claude_desktop_config.json`) — M

**Blocked by:** T2.

**What to build:** parsers that turn the three stdio MCP config shapes into
`McpServer` targets with per-field source locations.

**Acceptance criteria (tests first):**
- [ ] `parse` on a fixture `mcp.json` yields one `McpServer` per `mcpServers` key
      with `command`, `args`, `env`, `cwd` populated.
- [ ] The `command` field's `SourceLocation` points at the correct line/column in
      the raw file (positional JSON offset mapping).
- [ ] `.mcp.json` and `claude_desktop_config.json` fixtures parse to the same model.
- [ ] A file with no `mcpServers` key (or `servers` variant) returns `[]` (or the
      supported alias) without error.
- [ ] A malformed JSON file yields a single, actionable error finding (or a
      documented parse-error path), never a crash.

---

## T4 — Dependency manifest parsers (`package.json#mcpServers`, `requirements.txt`, `pyproject.toml`) — M

**Blocked by:** T2.

**What to build:** parsers producing both `McpServer` targets (from
`package.json#mcpServers`) and `Dependency` targets (from all three manifests),
with `pinned` computed.

**Acceptance criteria (tests first):**
- [ ] `package.json` with a `mcpServers` field yields `McpServer` targets plus
      `Dependency` targets for `dependencies`/`devDependencies`.
- [ ] `requirements.txt` yields one `Dependency` per line; `pinned` is true only
      for `==`/`===` specs.
- [ ] `pyproject.toml` yields `Dependency` targets from `[project] dependencies`
      and `[project.optional-dependencies]` (PEP 508).
- [ ] Version specs `*`, `latest`, `^1.0.0`, `~1.0.0`, and empty are flagged
      `pinned == false`; `==1.2.3` and `===` are `true`.
- [ ] Manifest files unrelated to dependencies (e.g. a `package.json` with no
      `mcpServers` and no deps) return `[]` or empty target lists without error.

---

## T5 — `SKILL.md` parser & Hermes layout discovery — M

**Blocked by:** T2.

**What to build:** a parser for `SKILL.md` (YAML frontmatter + markdown body,
line-indexed) and discovery that matches the Hermes
`profiles/*/skills/*/SKILL.md` layout.

**Acceptance criteria (tests first):**
- [ ] A `SKILL.md` fixture yields one `Skill` with `frontmatter` and a
      line-indexed `body`.
- [ ] Unknown frontmatter keys are tolerated (not an error).
- [ ] Discovery finds `SKILL.md` files nested under `profiles/*/skills/*/`.
- [ ] A `SKILL.md` with no frontmatter still yields a `Skill` with an empty
      `frontmatter` and the full body.
- [ ] A body line's `SourceLocation.line` matches the physical line number.

---

## T6 — Rule engine & rule registry — M

**Blocked by:** T2.

**What to build:** `RuleEngine.run(targets)` applying the enabled `Rule` set,
deduplicating identical findings, sorting deterministically, and honoring
enabled/disabled rules and a severity threshold.

**Acceptance criteria (tests first):**
- [ ] A trivial fake rule + a target yields the expected `Finding`s.
- [ ] Two rules producing the same finding yield one finding (dedup).
- [ ] Results are sorted by (path, line, rule id) regardless of insertion order.
- [ ] Disabled rules contribute no findings; the threshold filters lower-severity
      findings.
- [ ] `run([])` returns `[]` without error.

---

## T7 — Permission-excess rules — M

**Blocked by:** T3, T5, T6.

**What to build:** `MCP-shell-unrestricted`, `MCP-allow-all`, `MCP-broad-network`,
`MCP-broad-filesystem`, and `SKL-shell-execution`.

**Acceptance criteria (tests first):**
- [ ] An `mcp.json` server whose `command` is `sh`/`bash`/`powershell` triggers
      `MCP-shell-unrestricted` (error) at the `command` location.
- [ ] `args` containing `--allow-all` (or `-A`) triggers `MCP-allow-all`.
- [ ] `--allow-net` without a host restriction triggers `MCP-broad-network`;
      `--allow-net=example.com` does not.
- [ ] `--allow-read=/` (or `~`, `C:\`) triggers `MCP-broad-filesystem` (warning).
- [ ] A `Skill` body with an f-string shell invocation triggers
      `SKL-shell-execution` (warning) at the correct line.
- [ ] Benign fixtures (pinned args, restricted hosts) trigger nothing.

---

## T8 — Malicious-pattern rules — M

**Blocked by:** T5, T6.

**What to build:** `SKL-remote-code-exec`, `SKL-obfuscated-command`,
`SKL-sql-concatenation`.

**Acceptance criteria (tests first):**
- [ ] `curl … | sh` / `wget … | bash` in a skill body triggers
      `SKL-remote-code-exec` (error).
- [ ] A `base64 -d` (or `--decode`) payload in a shell command triggers
      `SKL-obfuscated-command` (warning).
- [ ] `f"SELECT … {var}"` and `"SELECT …" + var` trigger `SKL-sql-concatenation`
      (error); a parameterized `?` placeholder query does not.
- [ ] Each finding's line matches the offending line in the fixture.

---

## T9 — Dependency rule (`DEP-unpinned`) — S

**Blocked by:** T4, T6.

**What to build:** `DEP-unpinned`.

**Acceptance criteria (tests first):**
- [ ] An unpinned `requirements.txt` / `package.json` / `pyproject.toml`
      dependency triggers `DEP-unpinned` (warning) at the declaration line.
- [ ] Fully pinned dependencies trigger nothing.
- [ ] The finding message names the package and the unpinned spec.

---

## T10 — CLI UX, exit codes, text formatter & end-to-end docs — M

**Blocked by:** T6, T7, T8, T9.

**What to build:** the full `scan` surface — `--format sarif|text`,
`--output`, `--severity`, `--rules`, `--exclude-rule`, `--fail-on` — plus exit
codes, a human text formatter, and an end-to-end fixture proving the whole
pipeline on a realistic sample.

**Acceptance criteria (tests first):**
- [ ] `--format text` prints one line per finding (`[level] RULE — file:line:col — msg`).
- [ ] `--output file.sarif` writes the SARIF file; stdout stays clean.
- [ ] `--rules` and `--exclude-rule` restrict findings correctly.
- [ ] Exit code is 0 (no findings at/above `--fail-on`), 1 (findings present),
      2 (internal error, e.g. bad args).
- [ ] An end-to-end fixture (a repo with a bad `mcp.json`, an unpinned
      `requirements.txt`, and a malicious `SKILL.md`) yields the exact expected
      finding set, byte-identical across two runs.
- [ ] `README.md` documents install, usage, and CI snippet (no workflow file
      shipped in phase 1).
