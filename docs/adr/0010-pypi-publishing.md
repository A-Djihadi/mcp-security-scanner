# ADR-0010: PyPI publishing via Trusted Publishing (OIDC) and tag-triggered release

**Status:** accepted

## Context

Issue #8 wants the scanner published to PyPI with release automation. The repo
is public and already follows DevSecOps baseline (pinned actions, `permissions`
scoping, gitleaks in CI). Publishing introduces a permanent external side effect
and a credential surface; the design must minimize long-lived secrets and make
release reproducible and non-destructive. The distribution name must be final
before the first release.

## Decision

- **Distribution name:** `mcp-skill-scanner` (final). The originally assumed name
  `mcp-security-scanner` is already taken on PyPI by an unrelated tool, and a
  first candidate was rejected by PyPI for being too similar to existing
  projects (`mcpsec`, `mcpsecscan`), so the distribution is published under
  `mcp-skill-scanner`. The import module remains `mcpsec` and is unaffected by
  the distribution rename.
- **Auth: PyPI Trusted Publishing (OIDC).** The publish workflow authenticates
  to PyPI with an OIDC token from GitHub Actions (`id-token: write`, scoped to
  the publish job) instead of a long-lived API token — no secret is stored in
  the repo. This matches the standing DevSecOps rule "prefer OIDC over
  long-lived cloud keys."
- **Trigger:** a `v*` tag (e.g. `v0.1.0`) starts the release workflow. The tag
  is the only human action; everything else is automated.
- **Build & publish:** build `sdist` + `wheel` with `uv build`, publish with
  `pypa/gh-action-pypi-publish` (pinned by SHA) via trusted publishing. The
  publish job holds `permissions: { contents: read, id-token: write }` and
  nothing more.
- **Version source of truth:** `pyproject.toml` `[project].version`; the
  workflow **fails** if the tag and the project version disagree (no drift),
  via `scripts/check_tag_version.py`.
- **Protection:** a `v*` tag alone triggers the release. There is no protected
  environment and no required reviewers — the tag push is itself the
  deliberate, reviewed act.

## Considered options

- **Long-lived PyPI API token in a repo secret** — rejected: a permanent,
  high-value secret in the repo violates the OIDC-first rule and must be rotated
  manually.
- **Manual `uv publish` from a laptop** — rejected as the *only* path: not
  reproducible and no audit trail; kept as a documented escape hatch for the
  very first upload if trusted publishing can't be configured in one step.
- **Publish from `main` on every merge** — rejected: releases should be
  intentional and versioned, not implicit.
- **`setuptools-scm`/auto-versioning** — rejected for now: adds a build-time
  dependency and indirection; a single `pyproject.toml` version + tag check is
  simpler and sufficient.
- **Protected environment / required reviewers** — rejected: the owner chose a
  tag-only trigger; a protected environment would gate the release on manual
  approval rather than the tag itself.

## Consequences

- Releases are reproducible, tag-triggered, and carry no long-lived secret in
  the repo.
- Owner actions required before the first release: on PyPI, add a *pending
  trusted publisher* for owner `A-Djihadi`, repo `mcp-security-scanner`,
  workflow `release.yml`, environment blank; then push tag `v0.1.0` to trigger
  the first upload. No account or token may be created by an agent. Until then,
  everything up to the publish step (workflow file, tag/version check, build,
  smoke test) is delivered and verified locally.
