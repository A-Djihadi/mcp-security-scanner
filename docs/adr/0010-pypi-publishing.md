# ADR-0010: PyPI publishing via Trusted Publishing (OIDC) and tag-triggered release

**Status:** accepted (owner credentials pending — see Consequences)

## Context

Issue #8 wants the scanner published to PyPI with release automation. The repo
is public and already follows DevSecOps baseline (pinned actions, `permissions`
scoping, gitleaks in CI). Publishing introduces a permanent external side effect
and a credential surface; the design must minimize long-lived secrets and make
release reproducible and non-destructive. The distribution name is currently
assumed (`mcp-security-scanner`) and is cheap to rename before the first release.

## Decision

- **Distribution name:** `mcp-security-scanner` (assumed — **to verify**
  availability and ownership on PyPI; rename before the first release if taken).
- **Auth: PyPI Trusted Publishing (OIDC).** The publish workflow authenticates
  to PyPI with an OIDC token from GitHub Actions (`id-token: write`) instead of a
  long-lived API token — no secret is stored in the repo. This matches the
  standing DevSecOps rule "prefer OIDC over long-lived cloud keys."
- **Trigger:** a `v*` tag (e.g. `v0.1.0`) starts the release workflow. The tag
  is the only human action; everything else is automated.
- **Build & publish:** build `sdist` + `wheel` with `uv build`, publish with
  `pypa/gh-action-pypi-publish` (pinned by SHA) pointed at the trusted-publisher
  environment. `permissions: { contents: read, id-token: write }`.
- **Version source of truth:** `pyproject.toml` `[project].version`; the
  workflow **fails** if the tag and the project version disagree (no drift).
- **GitHub Release:** immutable — draft the release, attach the built artifacts,
  then publish. `latest`-style floating tags are not used.
- **Protection:** the publish job runs in a protected environment (required
  reviewers) so a release is a deliberate, reviewed act, not an accidental push.

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

## Consequences

- Releases are reproducible, reviewed, and carry no long-lived secret in the
  repo.
- Owner actions required before T24 can complete: create the PyPI account,
  reserve/confirm the name, and enable the repo as a trusted publisher
  (or authorize the one-off token for the first upload) — see
  `phase2-owner-actions.md`. No account or token may be created by an agent.
- Until the owner completes those actions, T24 is blocked at the publish step
  (everything else — workflow file, tag/version check, build — is unblocked).
