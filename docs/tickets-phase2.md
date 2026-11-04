# Tickets — mcp-security-scanner, Phase 2 (issues #3–#8)

Ordered, test-first tickets for the six Phase 2 GitHub issues. Same conventions
as `docs/tickets.md` (read `docs/coder-brief.md` first): a ticket's acceptance
criteria are tests to write FIRST (RED), then satisfy. Complexity scale:
**S** (≤1 day), **M** (1–2 days), **L** (2–3 days).

**Issue → ticket mapping (1:1 traceable):**

| GitHub issue | Ticket(s) |
|--------------|-----------|
| #3 semantic detection | T20, T21 |
| #4 registry-backed dep checks | T17, T18, T19 |
| #5 remote MCP servers | T14, T15, T16 |
| #6 `smithery.yaml` | T13 |
| #7 taint/flow analysis | T22, T23 |
| #8 publish to PyPI | T24 |

Foundational tickets (T11, T12) serve #4 and #5. Owner-gated tickets (T21, T23,
T24) are blocked on decisions in `docs/phase2-owner-actions.md`.

Dependency graph (Phase 1 T1–T10 is a prerequisite for all):

```
T11 ─┬─▶ T12 ─┬─▶ T16
     │         ├─▶ T17
     │         ├─▶ T18
     │         └─▶ T19
T13  (independent)
T14 ─▶ T15 ─▶ T16
T20 ─▶ T21
T22 ─▶ T23
T24  (independent, last — needs the package to stabilize)
```

---

## T11 — Online rule gating (`--online`) — M

**Blocked by:** Phase 1 (T1–T10 merged). Nothing new.

**What to build:** the capability flag that keeps the default scan offline. A
rule declares `online: bool = False`; `build_default_registry(*, online=False)`
excludes online rules by default; the CLI gains `--online`. The SARIF output
records the mode. See ADR-0007.

**Acceptance criteria (tests first):**
- [ ] A fake `online=True` rule is absent from `build_default_registry()` (no
      flag) and present in `build_default_registry(online=True)`.
- [ ] `mcpsec scan . --help` lists `--online`; running without it never
      constructs a network provider (assert no socket/`urlopen` is reached).
- [ ] A scan without `--online` is byte-identical to the phase-1 result over the
      same fixture (regression: add a fixture and assert two runs produce the
      same bytes and the same finding set as before).
- [ ] A finding from an online rule carries `properties.mode == "online"` in
      SARIF; a finding from an offline rule does not.
- [ ] With `--online`, `runs[0].properties.mcpsec.online == true`; without it,
      the property is `false` or absent (pick one and pin it in a test).
- [ ] `--online` + `--rules DEP-outdated` still respects `--exclude-rule`
      (interaction with the existing rule-select flags is covered).

---

## T12 — Data-source providers (registry + reachability) — M

**Blocked by:** T11.

**What to build:** `mcpsec/sources/` — the only layer that does network I/O.
Providers for OSV.dev, PyPI JSON API, npm registry, and an HTTP/SSE reachability
probe, all injected into rules at construction. Bounded timeout, bounded retry,
per-run memoization, typed `DataUnavailable` on any failure. See ADR-0007.

**Acceptance criteria (tests first):**
- [ ] A provider's `fetch` is mocked; the online rule receives it at
      construction and its `check()` performs no socket I/O (assert via a
      fake/recording provider).
- [ ] `DataUnavailable` is raised (not a crash) on timeout, HTTP error, malformed
      payload, and network refusal — each path covered.
- [ ] A 404 from PyPI/npm (unknown package) maps to a "no data" result, not an
      error finding and not an exception.
- [ ] Retries are bounded (exactly N attempts) and memoization prevents a second
      network call for the same key within one run (assert call count).
- [ ] Provider failures never change the exit code: a scan where every provider
      fails still exits 0/1 based only on deterministic findings.

---

## T13 — `smithery.yaml` parser — M

**Blocked by:** Phase 1. Independent of T11/T12.

**What to build:** a `SmitheryYamlParser` emitting `McpServer` targets. First
**verify the schema against the Smithery docs**, then pin the assumption with a
checked-in fixture. Grounded shape (to re-verify at implement time):
top-level `startCommand` (`type: stdio`; remote transport values **to verify**),
`configSchema` (a JSON Schema describing config, including `required` keys —
often secrets like `*ApiKey`/`*Token`), `commandFunction` (a JS function
`(config) => ({command, args, env})`), and `exampleConfig`.

**Acceptance criteria (tests first):**
- [ ] A `smithery.yaml` fixture with a `commandFunction` returning a literal
      `{command, args, env}` yields one `McpServer` with `command`, `args`, and
      `env` populated, `transport` derived from `startCommand.type`.
- [ ] A `startCommand.type` other than `stdio` (remote) sets
      `transport == "remote"`; the exact accepted values are pinned by a fixture
      and any unknown value is recorded as "to verify" rather than guessed.
- [ ] A `commandFunction` whose return is **not** statically extractable
      (dynamic/conditional) yields a `McpServer` with `command is None` and a
      `note`-level finding `MCP-parse-ambiguous` (or an equivalent documented
      parse-note) instead of a silent guess — never a crash.
- [ ] The `configSchema.required` keys are captured on the target (payload
      `config_required`) so rules can later flag secrets passed to `env`; each
      required key carries a `SourceLocation`.
- [ ] A `smithery.yaml` with no `startCommand` returns `[]` (or a documented
      parse-note) without error.
- [ ] `discover_files` includes `smithery.yaml` and the CLI maps it to the
      parser (extend `_SUPPORTED_NAMES` and the parser table).

---

## T14 — Remote MCP parser: `headers`, auth, transport — M

**Blocked by:** Phase 1 (extends `McpConfigParser`). Independent of T11/T12.

**What to build:** extend the existing `McpConfigParser` (and
`claude_desktop_config.json` + `package.json#mcpServers`) to capture the
remote-server fields the model already names but does not yet parse: `headers`
(map, with per-header `SourceLocation`), `url`, `type`, and the resolved
`transport`. See `docs/domain-model.md` (McpServer payload).

**Acceptance criteria (tests first):**
- [ ] A remote `mcp.json` entry (`url` + `type: "sse"`/`"http"`/`"streamable-http"`)
      yields `transport == "remote"` and a `url` with a `SourceLocation` pointing
      at the `url` value.
- [ ] `headers` parse into a `dict[str, str]` with per-header locations
      (each header key/value carries its own `SourceLocation`).
- [ ] A `package.json#mcpServers` remote entry and a `claude_desktop_config.json`
      remote entry produce the same model shape.
- [ ] A remote entry with no `url` but a remote `type` yields
      `transport == "remote"` and `url is None` (no crash; a later rule decides
      whether that is a finding).
- [ ] A stdio entry (command only) is unchanged: `transport == "stdio"`,
      `headers == {}`, `url is None`.

---

## T15 — Remote MCP offline hygiene rules — M

**Blocked by:** T14 (+ T6's engine, already shipped).

**What to build:** deterministic, offline rules over remote-server targets —
no network. Rule IDs and levels (final taxonomy in `docs/coder-brief.md`):

- `MCP-insecure-transport` (error) — `url` scheme is `http://` (plaintext)
  instead of `https://`/`wss://`.
- `MCP-header-secret` (warning) — a secret-looking literal in `headers`
  (e.g. `Authorization: Bearer <value>`, `X-API-Key: <value>`, `sk-…`/`ghp_…`
  patterns) — hardcoded credentials in config.
- `MCP-remote-no-auth` (note) — a remote server with no auth-bearing header;
  heuristic, "to verify" per client convention (documented).

**Acceptance criteria (tests first):**
- [ ] An `http://` remote URL triggers `MCP-insecure-transport` (error) at the
      `url` location; `https://` and `wss://` do not.
- [ ] A header `Authorization: Bearer sk-live-…` (and `X-API-Key`) triggers
      `MCP-header-secret` (warning) at the header location; a benign
      `Content-Type`/`Accept` header does not.
- [ ] A remote server with no `Authorization`/`X-API-Key` header triggers
      `MCP-remote-no-auth` (note); one with a bearer token does not.
- [ ] All three are pure: no I/O, no state; each is unit-tested through
      `check(target)` with hand-built `Target`s.
- [ ] Findings are sorted and deduped by the engine (no per-rule special-casing).

---

## T16 — Remote MCP reachability (online) — S

**Blocked by:** T11, T12, T14.

**What to build:** `MCP-unreachable` (online) — an `online=True` rule that
probes the remote server's `url` (via the reachability provider from T12) and
reports when the endpoint cannot be reached. Network findings never affect the
exit code. See ADR-0007.

**Acceptance criteria (tests first):**
- [ ] With a fake provider returning `unreachable`, a remote target yields
      `MCP-unreachable` (note) at the `url` location.
- [ ] With a fake provider returning `reachable`, no finding is produced.
- [ ] The rule is registered only under `--online`; a default scan over a remote
      `mcp.json` fixture produces **no** reachability finding and performs no
      network call (assert no provider is constructed).
- [ ] A provider raising `DataUnavailable` produces a note-level diagnostic
      (not `MCP-unreachable`, not an error) and the exit code is unchanged.
- [ ] The finding carries `properties.mode == "online"` in SARIF.

---

## T17 — `DEP-outdated` (online) — S

**Blocked by:** T11, T12 (+ T4's `Dependency` targets, already shipped).

**What to build:** `DEP-outdated` — compare a declared pinned version against
the latest from the registry (PyPI JSON API for `pyproject.toml` /
`requirements.txt`; npm registry for `package.json`). Online only.

**Acceptance criteria (tests first):**
- [ ] A pinned `flask==2.0.0` with a fake provider reporting latest `3.0.0`
      yields `DEP-outdated` (warning) naming the package, declared, and latest
      versions.
- [ ] A pinned dependency equal to the latest yields nothing.
- [ ] An **unpinned** dependency is skipped by `DEP-outdated` (it is
      `DEP-unpinned`'s concern) — no double-report.
- [ ] A 404 (unknown package) yields nothing (no false "outdated").
- [ ] The rule is `online=True`: absent from the default registry, present under
      `--online`; findings carry `properties.mode == "online"`.

---

## T18 — `DEP-known-vulnerability` via OSV.dev (online) — M

**Blocked by:** T11, T12.

**What to build:** `DEP-known-vulnerability` — query OSV.dev
`POST /v1/querybatch` for each resolved package (ecosystem+name+version, or
versioned purl), fetch full records for the returned IDs, and emit one finding
per vulnerability. Handles per-query pagination. See ADR-0007.

**Acceptance criteria (tests first):**
- [ ] A fake provider returning one vuln ID for a package yields
      `DEP-known-vulnerability` (error) naming package, version, and the vuln
      ID/severity (from the fetched record).
- [ ] A package with zero vulns yields nothing.
- [ ] A batch response with a `next_page_token` for one query triggers a
      follow-up fetch and does **not** drop that query's extra results
      (assert the provider is called again with the `page_token`).
- [ ] An unpinned dependency is skipped (only resolved versions are queried).
- [ ] `DataUnavailable` yields a note-level diagnostic, never an error finding,
      never a crash; exit code unaffected.
- [ ] `online=True`; findings carry `properties.mode == "online"`.

---

## T19 — `DEP-unknown` / typosquat (online) — M

**Blocked by:** T11, T12.

**What to build:** `DEP-unknown` — flag a declared package whose name is
suspiciously close to a popular package (typosquat signal) via
(Damerau-)Levenshtein distance against a popularity-ranked seed list. The seed
list source and threshold are **to verify**; the provider returns the list, the
rule stays pure.

**Acceptance criteria (tests first):**
- [ ] A fake provider returning `["requests", "flask", "numpy"]` flags
      `reqeusts` (distance ≤ threshold) as `DEP-unknown` (warning) naming the
      package and the near-match.
- [ ] A declared name that exactly matches a popular package yields nothing.
- [ ] A name beyond the distance threshold yields nothing.
- [ ] The threshold and the seed list are injected (not hardcoded) so the test
      pins both; the default seed-list source is recorded as "to verify".
- [ ] `online=True`; findings carry `properties.mode == "online"`.

---

## T20 — Semantic embedder seam + `SemanticRule` (offline, pluggable) — M

**Blocked by:** Phase 1. Independent of T11/T12.

**What to build:** the `Embedder` protocol (`embed(text) -> Sequence[float]`)
and `SemanticRule`, which computes cosine similarity of a skill's body (and
prose) against a curated, versioned reference corpus, emitting
`SKL-semantic-malicious` above a fixed threshold. No model is shipped here; the
embedder is injected. See ADR-0008.

**Acceptance criteria (tests first):**
- [ ] A fake embedder returning a high-similarity vector to a malicious anchor
      triggers `SKL-semantic-malicious` (warning) on a `Skill` target.
- [ ] A fake embedder returning a low-similarity vector yields nothing.
- [ ] The threshold is injected/configurable; a test pins the boundary
      (similarity == threshold resolves one way, documented and tested).
- [ ] The rule is deterministic given the same embedder + corpus (two identical
      runs yield identical findings).
- [ ] The corpus is versioned and injected; the finding's message names the
      matched anchor and the corpus version (so results are auditable).
- [ ] The rule is `online=False` (offline, deterministic) and runs by default
      **only when an embedder is explicitly configured** — a default scan with
      no embedder never calls the embedder (assert no embedder is constructed).

---

## T21 — Default local embedder + `[semantic]` optional dependency group — L

**Blocked by:** T20. **Owner-gated** — see `phase2-owner-actions.md`.

**What to build:** the default local embedder (a small, CPU-only,
license-permissive ONNX sentence-transformer — exact model **to verify** and
**owner-approved**) shipped as `[project.optional-dependencies] semantic = […]`,
so the base install stays PyYAML-only. `pip install mcp-security-scanner[semantic]`
opts in. See ADR-0008.

**Acceptance criteria (tests first):**
- [ ] `pyproject.toml` keeps `PyYAML` as the sole runtime dependency and adds a
      `semantic` optional-dependency group; a build without `[semantic]` does
      not pull the model runtime.
- [ ] Selecting the default embedder (via config/flag) loads it lazily; a scan
      without selection never imports the model runtime.
- [ ] The pinned model version + corpus are recorded on the finding/SARIF, and
      a change in either changes the recorded value (reproducibility under test).
- [ ] A golden fixture (a skill with adversarial prose) yields the expected
      `SKL-semantic-malicious` decision with the real embedder — one integration
      test, marked to skip if the optional group isn't installed.
- [ ] The model is pinned by exact version/hash (no floating spec) in the
      dependency group.

---

## T22 — Taint/flow: Python sources/sinks via stdlib `ast` — L

**Blocked by:** Phase 1. Independent (no network, no new dependency).

**What to build:** a deterministic Python taint analysis over an MCP server's
source tree using stdlib `ast`. Sources = MCP tool handler parameters (values
derived from request params); propagators = assignment/format/join/indexing/
returns; sinks = shell (`os.system`, `subprocess.*`, `Popen`), code eval
(`eval`/`exec`/`compile`), SQL (`execute`/`executemany`). Emits `FLOW-shell-injection`
(error), `FLOW-sql-injection` (error), `FLOW-code-eval` (warning). See ADR-0009.

**Acceptance criteria (tests first):**
- [ ] A fixture where a handler's parameter flows (via assignment and an f-string)
      into `subprocess.run([...])` triggers `FLOW-shell-injection` at the sink line.
- [ ] A fixture where a tainted value reaches `cursor.execute(f"SELECT … {x}")`
      triggers `FLOW-sql-injection`; a parameterized `execute(query, (x,))`
      does **not**.
- [ ] A fixture where tainted input reaches `eval()`/`exec()` triggers
      `FLOW-code-eval` (warning).
- [ ] Taint does **not** propagate through a recognized sanitizer (a documented
      escaping function) — a sanitized sink yields nothing.
- [ ] A benign fixture (constants only, no request-derived input) yields nothing.
- [ ] Analysis is pure and deterministic: two runs over the same tree yield
      identical, sorted, deduped findings; no network, no new dependency.
- [ ] Findings point at the sink's line/column in the source file.

---

## T23 — Taint/flow: JS/TS via `tree-sitter` — L

**Blocked by:** T22. **Owner-gated** — needs a new ADR for the `tree-sitter`
native dependency (see `phase2-owner-actions.md`). Can be deferred or descoped.

**What to build:** the JS/TS equivalent of T22 using `tree-sitter` + grammars.
Taint model mirrors T22 (request-derived input → shell/SQL/eval sinks).

**Acceptance criteria (tests first):**
- [ ] A JS fixture where a handler's argument reaches `child_process.exec(...)`
      triggers `FLOW-shell-injection` at the sink line.
- [ ] A TS fixture with `query += userInput` into `db.execute(query)` triggers
      `FLOW-sql-injection`; parameterized queries do not.
- [ ] Deterministic, sorted, deduped findings; the new dependency is declared in
      an ADR and an optional dependency group (base install unchanged).
- [ ] A benign fixture yields nothing.

---

## T24 — PyPI publish + release automation — M

**Blocked by:** Phase 2 features must be stable first (schedule last).
**Owner-gated** — see `phase2-owner-actions.md`.

**What to build:** a tag-triggered (`v*`) release workflow: build sdist+wheel
with `uv build`, publish via PyPI Trusted Publishing (OIDC) with
`pypa/gh-action-pypi-publish` (pinned SHA), create an immutable GitHub Release,
and fail the job if the tag and `pyproject.toml` version disagree. See ADR-0010.

**Acceptance criteria (tests first):**
- [ ] A script/test asserts the tag ↔ `pyproject.toml` version check fails on
      mismatch and passes on match (the check is extracted to a testable
      function, not only inline in the workflow).
- [ ] The workflow uses `permissions: { contents: read, id-token: write }` and
      pins every action by full SHA; `zizmor`/`actionlint` are run in CI to lint
      it (extend the existing CI).
- [ ] The distribution builds reproducibly: `uv build` produces both an sdist
      and a wheel, and `uv run pytest` passes against the built wheel in a clean
      venv (a smoke test).
- [ ] Publishing is guarded by an environment with required reviewers; the
      workflow does **not** publish from un-tagged pushes or PRs.
- [ ] The base runtime dependency set remains `PyYAML`-only in the published
      metadata.

---

## Recommended implementation order

1. **Parallel, unblocked now:** T11 (gating), T13 (`smithery.yaml`), T14
   (remote parser), T20 (semantic seam), T22 (Python taint).
2. **After T11:** T12 (providers).
3. **After T14:** T15 (remote hygiene); **after T11+T12+T14:** T16 (reachability).
4. **After T11+T12:** T17, T18, T19 (registry rules).
5. **After T20 (owner-gated):** T21. **After T22 (owner-gated):** T23.
6. **Last (owner-gated):** T24.

Owner decisions that gate T21, T23, and T24 are collected in
`docs/phase2-owner-actions.md` and must be resolved before those tickets start;
everything else is unblocked now.
