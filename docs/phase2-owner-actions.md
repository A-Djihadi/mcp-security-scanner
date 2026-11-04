# Phase 2 — Owner actions

Every decision below is **owner-only**: it needs Djihadi's answer, an account,
a credential, or approval an agent may not fabricate. Nothing here may be
resolved by an agent (no third-party accounts, no token requests). Each item
names the exact question, the ticket it gates, and the default if no answer is
given. Answer order matters: **the semantic and taint questions are independent
of PyPI; PyPI blocks only T24.**

## 1. Network access — approval (gates T16–T19)

**Question:** "Phase 2 adds opt-in network-backed rules (registry checks via
OSV.dev / PyPI / npm, and remote-server reachability), always behind `--online`
and never on by default. Do you approve the scanner making outbound HTTPS calls
to these endpoints when `--online` is passed?"

- Default / no answer: network rules stay behind `--online`; no network in the
  default scan (already decided by ADR-0007, but the *opt-in path itself* is
  what you're approving).
- Also confirm: is a narrower `--registry` flag (dependency-only) wanted now,
  or is `--online` enough for phase 2?

## 2. Semantic detection — model choice (gates T21; T20 unblocked now)

**Question:** "For semantic malicious-intent detection (#3), which backend do we
ship as the default? Recommendation is a **small local embedding model in an
optional dependency group** (offline, deterministic, no per-scan cost, base
install stays PyYAML-only). The alternatives are a **remote embedding API** or a
**remote generative model** (both need a vendor, cost, and an API key), or
**defer again**."

- **Pick one:** local embedder (recommended) / remote embedding API / remote
  generative model / defer.
- If **local**: approve adding a third-party runtime dep *in the `[semantic]`
  optional group*, and name or approve a specific small CPU-only model — size,
  license, and current availability are **to verify**; I need your sign-off on
  the "small, CPU-only, license-permissive" criteria (ADR-0008), not a model I
  invent.
- If **remote**: name the vendor and confirm you'll provide the API key and
  budget; pricing, terms, and capabilities are **to verify** against the vendor.

## 3. Taint analysis — language scope (gates T23; T22 unblocked now)

**Question:** "Taint/flow analysis (#7) is scoped to **Python only** in phase 2,
using the standard library `ast` (no new dependency). Extending to
JavaScript/TypeScript requires adding `tree-sitter` + grammars — a native
dependency needing its own ADR. Do we add `tree-sitter` for JS/TS now, defer it,
or drop JS/TS entirely?"

- **Pick one:** defer JS/TS (recommended — ship Python-only first) / add
  `tree-sitter` now / drop JS/TS.
- If **add now**: you're approving a new native dependency + a new ADR (T23).

## 4. PyPI — account, name, trusted publishing (gates T24)

**Question:** "To publish to PyPI (#8) I need from you, in order:"

1. **Account** — confirm the PyPI account (and Org, if publishing under an
   org). *Do not* share a password; I will never create the account.
2. **Distribution name** — `mcp-security-scanner` is assumed. Confirm it, or
   give the real name if it's taken (rename is cheap before the first release —
   I need the final string before the first publish, but T24 work can proceed
   on the assumed name).
3. **Trusted Publishing** — approve the OIDC flow (no long-lived token): you
   configure the PyPI project to trust the GitHub repo (or authorize a
   one-time, upload-scoped API token for the very first publish, then switch to
   trusted publishing). Which do you prefer?
4. **Protection** — should the publish job require an approving reviewer
   (protected environment), or is a tag alone sufficient?

- Default / no answer: T24 stays blocked at the publish step; the workflow
  file, version check, and build are still deliverable and tested locally.

## 5. (Informational, no action) Typosquat seed list — T19

Not a hard block: T19 needs a popularity-ranked package-name seed list. I'll
source it at implement time and mark the exact source **to verify** (license
and cacheability). No owner decision needed unless you have a preferred source.

---

## Summary of what is blocked vs. unblocked

| Blocked on owner | Ticket(s) |
|------------------|-----------|
| Nothing | T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T22 |
| #2 (model choice) | T21 |
| #3 (tree-sitter) | T23 |
| #4 (PyPI account/name/OIDC) | T24 |

T16–T19 additionally require #1 (network-access approval) before any real
network call is exercised in CI, but their offline tests and provider mocks can
proceed regardless.
