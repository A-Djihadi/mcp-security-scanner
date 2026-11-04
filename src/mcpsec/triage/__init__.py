"""LLM-assisted triage of mcpsec findings (optional ``agent`` extra, ADR-0011).

The deterministic scan stays the source of truth: triage only *explains* each
finding and proposes a fix. It never adds, removes or re-levels a finding and
never changes the exit code.
"""
