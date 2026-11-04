# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — versioning: [SemVer](https://semver.org/).

## [Unreleased]
### Added
- `mcpsec triage`: advisory LLM explanation and fix for each finding, orchestrated with
  LangGraph (`Send` fan-out, per-finding subgraph, grounding guardrail, rules fallback),
  traced in self-hosted Langfuse; optional `agent` extra (ADR-0011).
- `MCP-inline-code` (warning): `python -c`, `node -e`, `ruby -e`, `perl -e`, `php -r`.
- `scan --exclude GLOB` to skip paths (fixtures, virtualenvs).
- CI: ruff lint (pinned, fixtures excluded), self-scan with SARIF upload, CodeQL, Dependabot
  (actions + uv); `SECURITY.md`.
- README: the 12 rules added in phase 2 (`FLOW-*`, remote MCP, online `DEP-*`) and `--online`.

### Security
- `--online`: the HTTP client fetched any URL scheme taken from a scanned config. A hostile
  `mcp.json` could make the scanner open local files (`file:///…`, or `file:///dev/zero`
  to exhaust memory) or probe internal services and cloud metadata (`169.254.169.254`)
  from CI. Now: `http(s)` only, response bodies capped at 10 MiB, and the reachability
  probe refuses loopback, private, link-local and unresolvable hosts.

### Fixed
- `MCP-shell-unrestricted` missed `dash`, `ash`, `ksh`, `mksh`, `fish`, `csh`, `tcsh` and
  shells started through a launcher (`env bash -c …`, `sudo sh`).
- `MCP-broad-network` missed `--allow-net=` with an empty value.
- README CI example: `uv run` does not work outside this repo (now `uvx --from git+…`),
  missing `security-events: write`, actions now pinned by SHA.

## [0.1.0]
### Added
- Deterministic scanner MVP: MCP configs, skills, dependency manifests; 9 rules; SARIF 2.1.0.
