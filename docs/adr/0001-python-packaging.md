# ADR-0001: Python 3.13, uv packaging, minimal dependencies

**Status:** accepted

## Context

The scanner is a greenfield CLI tool. Language (Python, 3.13) is fixed by the
project brief. Still open: how to package, and which third-party dependencies to
allow.

## Decision

Package with **uv** (`uv init`, `pyproject.toml` with the `uv`/PEP 621 build
backend), targeting **Python 3.13**. Import package is `mcpsec`; distribution
name is `mcp-security-scanner`. The **only runtime dependency is PyYAML**
(needed for `SKILL.md` frontmatter and any YAML manifests). Everything else is
the standard library: `json`, `argparse`, `pathlib`, `re`, `dataclasses`,
`hashlib`. `pytest` is a dev dependency.

## Considered options

- **Poetry / pip** — the local environment has a `pip`/`python` version mismatch
  (pip points at 3.15 while `python3` is 3.13). `uv` sidesteps this cleanly and
  is already installed.
- **Zero runtime deps (hand-rolled YAML)** — rejecting: YAML frontmatter parsing
  is easy to get wrong (nested lists, quoting, multi-line scalars). PyYAML is
  free, offline-installable, and has no network or paid-API implication.
- **A SARIF library** (`sarif-om`, `pysarif`) — rejecting: the writer is a small
  projection and a hand-written writer keeps the schema under our control; a
  dependency buys little.

## Consequences

- Reproducible installs via `uv sync` / `uv run`.
- No paid API, no scan-time network: the constraint is structural, not just a
  promise.
- PyYAML is the sole supply-chain surface in the runtime dependency set, which
  keeps the tool itself auditable (fitting for a security tool).
