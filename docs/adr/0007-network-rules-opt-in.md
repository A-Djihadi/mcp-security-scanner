# ADR-0007: Network-backed rules are opt-in; deterministic-offline stays the default

**Status:** accepted

## Context

Phase 2 adds two rule families that need the network: registry-backed dependency
checks (#4: `DEP-outdated`, `DEP-known-vulnerability`, `DEP-unknown`) and remote
MCP-server reachability (#5). The hard constraint from the brief is that the
**default scan stays fully offline, deterministic, and byte-identical**. This ADR
defines how those rules are gated, how their I/O is isolated so the "pure rule"
invariant survives, and how consumers can tell deterministic findings from
network-dependent ones. It supersedes ADR-0006 for the gating mechanics; the
dependency-specific data-source decision is refined below.

## Decision

### Gating

- A rule declares `online: bool = False` (class attribute). `online=True` means
  the rule's result depends on data that only exists on the network.
- `build_default_registry(*, online: bool = False) -> RuleRegistry` includes
  online rules **only** when `online=True`. The default (`False`) registry is
  exactly the phase-1 rule set, so a scan without the flag is byte-identical to
  phase 1 (regression-guarded by test).
- The CLI exposes a single master switch, **`--online`**. Without it, no network
  rule is registered and no network I/O happens. (A narrower `--registry` alias
  for dependency-only online checks is a trivial future addition if the owner
  wants finer control; phase 2 ships `--online` only.)

### I/O isolation (preserving pure rules)

- All network I/O lives in a **provider layer** (`mcpsec/sources/`), never in a
  rule. An online rule receives its provider **injected at construction**
  (the same seam ADR-0005 reserved for `SemanticRule`: "a lookup injected at
  construction").
- `Rule.check(target)` stays I/O-free in the strict sense for files; for online
  rules the purity contract is restated as **deterministic over
  `(target, provider-output)`**: same provider response ⇒ same findings, no
  randomness, no mutable state. Determinism across *runs* is explicitly
  *not* guaranteed when `--online` is set, and the output says so.
- Provider contract: bounded timeout, bounded retry, per-run memoization,
  and a typed `DataUnavailable` error for any network/HTTP/parse failure.
  A failure **never crashes and never produces a verdict**: it surfaces as a
  `note`-level diagnostic finding (or a SARIF `notification`), and network
  findings never contribute to the exit code — only deterministic findings
  drive the `--fail-on` gate.

### SARIF marking

- Every finding from an online rule carries `results[].properties.mode = "online"`.
- The `run` records `properties.mcpsec.online = true` when the scan ran online,
  so a consumer (and a determinism test) can reject or quarantine the run.

### Data sources (refines ADR-0006)

- **Known vulnerabilities:** OSV.dev `POST /v1/querybatch` (batch by
  ecosystem+name+version, or versioned purl; response returns vuln IDs +
  `modified` in input order; paginate via per-query `next_page_token`; full
  records via `GET /v1/vulns/{id}`). No rate limit is documented today, but a
  ~32 MiB response cap applies over HTTP/1.1 — **to verify** the practical
  limits before shipping.
- **Outdated / latest:** PyPI JSON API (`https://pypi.org/pypi/<name>/json`)
  and npm registry (`https://registry.npmjs.org/<name>`). Rate limits and ToS
  of both registries are **to verify** before shipping; the provider must be
  written to tolerate a 404 (unknown package) as a normal, non-verdict result.
- **Typosquat/unknown:** Levenshtein (or Damerau-Levenshtein) distance against a
  popularity-ranked name list. The exact seed list (PyPI "top N", npm
  "top N", or a curated allowlist) is an owner/design decision left to T19 and
  is **to verify** for a licenseable, offline-cacheable source.

## Considered options

- **Run network rules by default with a `--offline` escape hatch** — rejected:
  inverts the default and breaks the offline/deterministic/CI-safe guarantee the
  whole phase-1 design rests on (ADR-0001, ADR-0002).
- **Fetch data inside `check()`** — rejected: breaks the pure-rule invariant and
  makes rules untestable without a live network; injection-at-construction keeps
  `check()` deterministic-over-inputs.
- **Bundle a snapshot DB** (as ADR-0006 noted) — rejected for the same reasons
  as before (stale by construction, no owner); the provider layer can *optionally*
  cache responses to disk later without changing the rule surface.

## Consequences

- The default scan remains offline, deterministic, byte-identical, and free.
- Adding a network rule = one class with `online=True` + one provider + tests;
  no engine changes.
- Determinism is now a *mode*, recorded in the SARIF output, not a silent
  assumption.
- New seam `mcpsec/sources/` is the single place network, rate limits, retries,
  and error taxonomy live; rules stay pure.
