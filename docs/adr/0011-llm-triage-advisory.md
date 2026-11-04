# ADR-0011: LLM triage of findings — advisory, local, guarded

**Status:** accepted

## Context

A SARIF report tells a developer *what* rule fired and *where*. It does not explain
*why* it matters in their file or *how* to fix it, which is where findings get ignored.
A local LLM can write that explanation. ADR-0002 and ADR-0008 rule out an LLM for
**detection** (non-deterministic, not offline-by-default). Explaining a finding the
deterministic engine already produced is a different job, and the risks are different:
the scanned files are untrusted and may contain instructions aimed at the model.

## Decision

1. **New subcommand `mcpsec triage`**, in an optional `agent` extra
   (`langgraph`, `langfuse`). The base install stays PyYAML-only (ADR-0001).
2. **Advisory only.** Triage runs the normal deterministic scan, then explains each
   finding. It never adds, removes or re-levels a finding; rule id, level, location and
   message are copied from the engine, never from the model. Exit code is always 0:
   `mcpsec scan` remains the CI gate.
3. **Orchestration with LangGraph.** One branch per finding, fanned out with `Send`
   and merged with a list reducer; a per-finding subgraph
   `load_context -> explain -> (done | explain again | fallback_rules)`.
4. **Guardrails against prompt injection and hallucination.** The file excerpt is sent
   inside an `<CONTEXT untrusted="true">` block with an explicit instruction not to obey
   it; the model's `evidence` must be a line that really exists in the excerpt, otherwise
   one stricter retry, then a deterministic, rule-based explanation. Secrets are redacted
   before the model and before tracing.
5. **Local model only by default** (Ollama, `OLLAMA_URL` / `OLLAMA_MODEL`): no API key,
   no data leaving the machine.
6. **Observability with Langfuse** (self-hosted, optional): a span per graph node, a
   generation per model call (model, tokens), a `grounded` score per answer and a
   `grounded_ratio` per run. Disabled (no-op) without `LANGFUSE_*` keys.

## Considered options

- **LLM as a detector** — rejected (ADR-0002, ADR-0008): breaks determinism and the CI gate.
- **Remote model API** — rejected as default: cost, key management, code leaves the host.
- **Plain loop instead of LangGraph** — workable, but the graph makes the retry/fallback
  decisions explicit, testable edge by edge, and visible in traces.

## Consequences

- The scan's guarantees (offline, deterministic, gateable) are unchanged.
- Triage quality depends on the local model; the `grounded` score makes weak answers
  visible instead of silently shipping them, and the rules fallback bounds the worst case.
- Two optional dependencies to keep updated (Dependabot covers `uv`).
