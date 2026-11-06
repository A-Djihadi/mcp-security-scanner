"""Langfuse tracing for triage (no-op when langfuse or its keys are absent)."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager

try:
    from langfuse import Langfuse, propagate_attributes
except ImportError:  # pragma: no cover
    Langfuse = None
    propagate_attributes = None

_SECRET = re.compile(
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{16,}\b"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}\b|(?i:bearer\s+[A-Za-z0-9._~+/=-]{16,})"
)

_client = None


def redact(text: str) -> str:
    return _SECRET.sub("[REDACTED]", text)


def mask(*, data, **_):
    """Mask secrets in everything exported to Langfuse (strings, dicts, lists)."""
    if isinstance(data, str):
        return redact(data)
    if isinstance(data, dict):
        return {k: mask(data=v) for k, v in data.items()}
    if isinstance(data, list):
        return [mask(data=v) for v in data]
    return data


def enabled() -> bool:
    return (Langfuse is not None
            and os.environ.get("LANGFUSE_DISABLED", "").lower() not in ("1", "true")
            and bool(os.environ.get("LANGFUSE_PUBLIC_KEY"))
            and bool(os.environ.get("LANGFUSE_SECRET_KEY")))


def client(**kwargs):
    global _client
    if _client is None and (enabled() or kwargs):
        _client = Langfuse(mask=mask, environment=os.environ.get("MCPSEC_ENV", "local"), **kwargs)
    return _client


def reset() -> None:
    global _client
    _client = None


def callbacks() -> list:
    if client() is None:
        return []
    from langfuse.langchain import CallbackHandler
    return [CallbackHandler()]


@contextmanager
def trace(name: str, *, tags=None, metadata=None, input=None):
    lf = client()
    if lf is None:
        yield None
        return
    attrs = {k: str(v) for k, v in (metadata or {}).items()}
    with (
        lf.start_as_current_observation(name=name, as_type="agent", input=input) as root,
        propagate_attributes(tags=tags or [], trace_name=name, metadata=attrs),
    ):
        yield root


@contextmanager
def span(name: str, as_type: str = "span", **kwargs):
    lf = client()
    if lf is None:
        yield None
        return
    with lf.start_as_current_observation(name=name, as_type=as_type, **kwargs) as s:
        yield s


def score_observation(observation, name: str, value, comment=None) -> None:
    if observation is not None:
        observation.score(name=name, value=value, comment=comment)


def score_trace(name: str, value, comment=None) -> None:
    lf = client()
    if lf is not None:
        lf.score_current_trace(name=name, value=value, comment=comment)


def flush() -> None:
    if _client is not None:
        _client.flush()
