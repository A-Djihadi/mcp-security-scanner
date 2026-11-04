"""Triage graph (LangGraph): one branch per finding, fanned out with ``Send``.

Parent graph::

    START --(Send x N)--> triage_finding --> report --> END

Per-finding subgraph (``triage_finding`` runs it, so each branch is its own
span in Langfuse)::

    load_context -> explain --(grounded)----------------> done
                       |  \\--(not grounded, 1st try)--> explain (stricter)
                       \\----(Ollama down / 2nd miss)----> fallback_rules -> done

Guardrails, because the context comes from the scanned file and is untrusted:
- the model only fills ``explanation``/``fix``/``evidence``; rule id, level,
  location and message are copied from the deterministic finding, never from
  the model;
- ``evidence`` must be a line that really is in the context (grounding check),
  otherwise the answer is retried once, then replaced by a rule-based text;
- secrets are redacted from the context before the model and before Langfuse.
"""

from __future__ import annotations

import operator
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from . import tracing
from .llm import SYSTEM_PROMPT, build_user_message, chat

CONTEXT_RADIUS = 4
MAX_ATTEMPTS = 2
MAX_FIELD_CHARS = 600

# Deterministic remediation used when the model is unavailable or ungrounded.
REMEDIATION = {
    "MCP-shell-unrestricted": "Replace the shell with the server's own executable and pass "
                              "explicit arguments; never let the agent compose shell strings.",
    "MCP-allow-all": "Remove --allow-all and grant only the permissions the server needs "
                     "(--allow-read=<dir>, --allow-net=<host>).",
    "MCP-broad-network": "Restrict network access to the hosts the server needs: "
                         "--allow-net=api.example.com.",
    "MCP-broad-filesystem": "Scope filesystem access to a project directory instead of / or ~.",
    "MCP-inline-code": "Move the inline code into a versioned script file and run that file.",
    "SKL-shell-execution": "Pass arguments as a list (subprocess.run([...], shell=False)) and "
                           "validate the input against an allow-list.",
    "SKL-remote-code-exec": "Download to a file, verify its checksum or signature, review it, "
                            "then execute it; never pipe a URL into a shell.",
    "SKL-obfuscated-command": "Replace the base64 payload with the readable command so it can "
                              "be reviewed.",
    "SKL-sql-concatenation": "Use parameterized queries (placeholders) instead of string "
                             "concatenation.",
    "DEP-unpinned": "Pin the version (==x.y.z) or commit a lockfile so builds are reproducible.",
}


class TriageState(TypedDict, total=False):
    root: str
    findings: list[dict]
    triaged: Annotated[list[dict], operator.add]   # reducer: branches append in parallel


class ItemState(TypedDict, total=False):
    root: str
    finding: dict
    context: str
    attempts: int
    answer: dict
    llm_error: str
    result: dict


# ------------------------------------------------------------ per-finding nodes

def load_context(state: ItemState) -> ItemState:
    f = state["finding"]
    path = Path(state["root"]) / f["path"]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"context": f["message"], "attempts": 0}
    line = f.get("line") or 1
    lo, hi = max(1, line - CONTEXT_RADIUS), min(len(lines), line + CONTEXT_RADIUS)
    ctx = "\n".join(f"{n:>4} | {lines[n - 1]}" for n in range(lo, hi + 1))
    return {"context": tracing.redact(ctx), "attempts": 0}


def explain(state: ItemState) -> ItemState:
    attempt = state.get("attempts", 0) + 1
    system = SYSTEM_PROMPT
    if attempt > 1:
        system += ("\nYour previous evidence was not found in CONTEXT. Copy one line "
                   "EXACTLY as it appears after the '|' separator.")
    user = build_user_message(state["finding"], state["context"])
    with tracing.span("ollama-triage", as_type="generation", input=user,
                      metadata={"attempt": attempt, "rule": state["finding"]["rule_id"]}) as gen:
        try:
            answer, meta = chat(system, user)
        except Exception as exc:  # noqa: BLE001 - Ollama down, timeout or invalid JSON: all degrade to rules
            if gen is not None:
                gen.update(level="ERROR", status_message=str(exc))
            return {"attempts": attempt, "llm_error": str(exc)}
        if gen is not None:
            gen.update(output=answer, model=meta["model"],
                       model_parameters=meta["model_parameters"], usage_details=meta["usage"])
            tracing.score_observation(gen, "grounded", float(_grounded(answer, state["context"])))
    return {"attempts": attempt, "answer": answer, "llm_error": ""}


def fallback_rules(state: ItemState) -> ItemState:
    f = state["finding"]
    return {"result": _result(f, explanation=f["message"],
                              fix=REMEDIATION.get(f["rule_id"], "Review this finding manually."),
                              evidence=f.get("snippet") or "", source="rules", grounded=False)}


def done(state: ItemState) -> ItemState:
    a = state["answer"]
    return {"result": _result(state["finding"],
                              explanation=_clip(a.get("explanation")), fix=_clip(a.get("fix")),
                              evidence=_clip(a.get("evidence")), source="llm", grounded=True)}


def route(state: ItemState) -> Literal["done", "explain", "fallback_rules"]:
    if state.get("llm_error"):
        return "fallback_rules"
    if _grounded(state.get("answer") or {}, state["context"]):
        return "done"
    return "explain" if state.get("attempts", 0) < MAX_ATTEMPTS else "fallback_rules"


def _grounded(answer: dict, context: str) -> bool:
    ev = answer.get("evidence")
    if not isinstance(ev, str) or len(ev.strip()) < 4:
        return False
    ev = ev.strip()
    code_lines = [ln.split("|", 1)[-1].strip() for ln in context.splitlines()]
    return any(ev in ln or (len(ln) >= 4 and ln in ev) for ln in code_lines if ln)


def _clip(value) -> str:
    text = value if isinstance(value, str) else ""
    return text.strip()[:MAX_FIELD_CHARS]


def _result(f: dict, *, explanation, fix, evidence, source, grounded) -> dict:
    # Identity fields always come from the deterministic finding, never from the model.
    return {**{k: f[k] for k in ("rule_id", "level", "path", "line", "column", "message")},
            "explanation": explanation, "fix": fix, "evidence": evidence,
            "source": source, "grounded": grounded}


def build_item_graph():
    g = StateGraph(ItemState)
    g.add_node("load_context", load_context)
    g.add_node("explain", explain)
    g.add_node("fallback_rules", fallback_rules)
    g.add_node("done", done)
    g.add_edge(START, "load_context")
    g.add_edge("load_context", "explain")
    g.add_conditional_edges("explain", route)
    g.add_edge("fallback_rules", END)
    g.add_edge("done", END)
    return g.compile()


# ------------------------------------------------------------ parent graph

_ITEM = None


def triage_finding(state: ItemState, config=None) -> TriageState:
    global _ITEM
    _ITEM = _ITEM or build_item_graph()
    out = _ITEM.invoke({"root": state["root"], "finding": state["finding"]}, config)
    return {"triaged": [out["result"]]}


def fan_out(state: TriageState) -> list[Send]:
    return [Send("triage_finding", {"root": state["root"], "finding": f})
            for f in state["findings"]]


def report(state: TriageState) -> TriageState:
    order = {"error": 0, "warning": 1, "note": 2}
    ordered = sorted(state.get("triaged", []),
                     key=lambda r: (order.get(r["level"], 3), r["path"], r["line"] or 0, r["rule_id"]))
    grounded = sum(1 for r in ordered if r["grounded"])
    tracing.score_trace("grounded_ratio", round(grounded / len(ordered), 2) if ordered else 1.0)
    return {"triaged": [], "findings": ordered}  # `findings` now carries the sorted report


def build():
    g = StateGraph(TriageState)
    g.add_node("triage_finding", triage_finding)
    g.add_node("report", report)
    g.add_conditional_edges(START, fan_out, ["triage_finding"])
    g.add_edge("triage_finding", "report")
    g.add_edge("report", END)
    return g.compile()


def run(root: str, findings: list[dict], *, max_concurrency: int = 2) -> list[dict]:
    """Triage findings (dicts with rule_id, level, path, line, column, message, snippet)."""
    if not findings:
        return []
    config = {"callbacks": tracing.callbacks(), "max_concurrency": max_concurrency}
    with tracing.trace("mcpsec.triage", tags=["mcpsec", "langgraph"],
                       metadata={"findings": len(findings)},
                       input={"root": root, "findings": len(findings)}) as root_span:
        state = build().invoke({"root": root, "findings": findings}, config)
        if root_span is not None:
            root_span.update(output={"triaged": len(state["findings"]),
                                     "llm": sum(r["source"] == "llm" for r in state["findings"])})
    tracing.flush()
    return state["findings"]
