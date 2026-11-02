# ADR-0006: Dependency policy — pinning checks only (offline) in MVP

**Status:** accepted

## Context

The brief lists "unpinned", "unknown", and "outdated" dependencies as risks.
"Unpinned" is computable locally and deterministically. "Outdated" and "unknown
(typosquat)" require external data (registry metadata, a vulnerability/package
advisory feed) and therefore network access, rate limits, and a data source
decision.

## Decision

The MVP implements **`DEP-unpinned` only** — a purely local, deterministic check
across `package.json`, `requirements.txt`, and `pyproject.toml`. Registry-backed
rules (`DEP-outdated`, `DEP-unknown`, `DEP-known-vulnerability`) are **phase 2**.
They will be gated behind an explicit opt-in flag (e.g. `--online`) and a
documented data source (OSV.dev is the candidate; free, no paid API — "to
verify" against its rate limits and ToS), so the default scan stays offline and
costless.

## Considered options

- **Query npm/PyPI registries at scan time** — rejecting for MVP: breaks the
  offline/deterministic guarantee and adds latency and failure modes to CI.
- **Bundle a snapshot DB of package versions** — rejecting: stale by
  construction, and a maintenance burden with no clear owner.
- **Use OSV.dev in the MVP** — deferred to phase 2 as the opt-in online path;
  it is free but still network-dependent, so it does not belong in the
  deterministic default.

## Consequences

- The default scan is reproducible and free (no paid API, no network).
- `DEP-unpinned` is the only dependency rule a CI gate can rely on in phase 1.
- The `--online` flag is a reserved, unimplemented seam for phase 2; it is
  documented but not shipped.
