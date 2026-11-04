# ADR-0008: Semantic detection — local, optional, offline embedder behind the Rule seam

**Status:** accepted (owner decision pending — see Consequences)

**Supersedes:** ADR-0005.

## Context

Issue #3 wants malicious-*intent* detection beyond syntactic signatures:
suspicious instruction patterns in skills that look benign syntactically
(e.g. a skill whose prose tells the agent to exfiltrate data). ADR-0005 deferred
this and reserved the `Rule` protocol as the seam. Phase 2 must pick an approach
without breaking the two non-negotiables — the default scan stays offline and
deterministic, and no new third-party *runtime* dependency enters the base
install without justification.

The decisive fact: **embedding a fixed text with a fixed model is a deterministic
function.** No sampling, no temperature. So a local embedding model preserves
*both* guarantees (offline *and* byte-identical given a pinned model), which a
remote or generative model cannot.

## Decision

Ship semantic detection as a **pluggable `SemanticRule` behind the existing
`Rule` interface, with a small local embedder in an optional dependency group —
and no model in the base install.**

- **Interface:** `Embedder` protocol — `embed(text: str) -> Sequence[float]` —
  injected into `SemanticRule` at construction (ADR-0005's reserved seam).
- **Rule behaviour:** `SemanticRule.check(skill_target)` embeds the skill's body
  (and, separately, its prose instructions), computes cosine similarity against
  a **curated, versioned reference corpus** of malicious and benign embeddings,
  and emits `SKL-semantic-malicious` when the similarity to a malicious anchor
  exceeds a **fixed, configurable threshold**. No model is downloaded or loaded
  unless the embedder is explicitly installed and selected.
- **Determinism:** pinned model version + pinned corpus + fixed threshold ⇒
  deterministic and offline. (A different model/corpus version changes results;
  both are recorded so the fingerprint stays honest.)
- **Optional dependency group:** the default embedder ships as
  `[project.optional-dependencies] semantic = [...]`, so
  `pip install mcp-security-scanner` keeps its single `PyYAML` runtime
  dependency (ADR-0001), and `pip install mcp-security-scanner[semantic]`
  opts into the heavier install.
- **Default embedder:** a small ONNX sentence-transformer (small, license-
  permissive, CPU-only). The exact model (name, size, license) is an owner
  decision — **to verify** current models and sizes; the ADR commits to "small,
  CPU-only, license-permissive, pinned by hash/version" as the selection
  criteria, not to a specific model.

## Considered options

| Option | Offline | Deterministic | Base install | Cost | Verdict |
|--------|---------|---------------|--------------|------|---------|
| **Local embedder, optional group** | yes | yes (pinned model) | unchanged (`[semantic]` opt-in) | none per scan; one-time model download | **recommended** |
| **Remote embedding API** | no | no | unchanged | per-call; needs API key | rejected as default (network + cost + key), kept viable as a plug-in behind the same `Embedder` |
| **Remote generative classifier (LLM)** | no | no | unchanged | per-call; needs key | rejected for the default (nondeterministic, cost, key); same plug-in path |
| **Ship the model in the base install** | yes | yes | heavy (hundreds of MB) | none per scan | rejected — violates the light-base-install principle |
| **Defer again / syntactic only** | yes | yes | unchanged | none | kept as fallback if the owner rejects any new dependency |

The owner decision is **which row to build first** (see `phase2-owner-actions.md`):
recommendation is the local optional embedder; the remote-API path is designed
for but not built by default.

## Consequences

- `SKL-semantic-malicious` is a real, testable rule via the `check(target)` seam;
  its embedder is fakeable in unit tests, so the rule logic is fully covered
  without a network or a model.
- The base install stays `PyYAML`-only; the semantic feature is an explicit,
  documented opt-in.
- An owner decision is required before T21 (which model / or which remote vendor)
  can be implemented; T20 (the seam) is unblocked now and can proceed.
- Determinism now depends on pinned model + corpus versions; the SARIF finding
  records them so results are reproducible and auditable.
